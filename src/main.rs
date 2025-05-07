mod layout;

use std::{ fs, io };
use std::io::{ BufRead, Read, Write };
use std::path::PathBuf;
use std::cell::RefCell;
use std::collections::{ hash_map, HashMap, HashSet };
use anyhow::Context;
use argh::FromArgs;
use prost::Message;
use micromegas_perfetto::protos::{ Trace, TracePacket, EventName, SourceLocation, trace_packet, track_event };

/// sftrace tools
#[derive(FromArgs)]
struct Options {
    #[argh(subcommand)]
    subcmd: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Convert(ConvertCommand),
    Extract(ExtractCommand)
}

/// Convert command
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "convert")]
struct ConvertCommand {
    /// sftrace trace path
    #[argh(positional)]
    path: PathBuf,

    /// debug symbol path
    #[argh(option, short = 's')]
    symbol: Option<PathBuf>,

    /// chrome-trace output path
    #[argh(option, short = 'o')]
    output: PathBuf,    
}

/// Extract command
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "extract")]
struct ExtractCommand {
    /// object file
    #[argh(positional)]
    path: PathBuf,

    /// filter by rlib
    #[argh(option, short = 'r')]
    rlibs: Option<String>,

    /// filter-file output path
    #[argh(option, short = 'o')]
    output: PathBuf,    
}

fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    match options.subcmd {
        SubCommand::Convert(cmd) => convert(&cmd),
        SubCommand::Extract(cmd) => extract(&cmd)
    }
}

fn convert(options: &ConvertCommand) -> anyhow::Result<()> {
    let log = fs::File::open(&options.path)?;
    let mut log = io::BufReader::new(log);

    // check sign
    {
        let mut sign = [0; layout::SIGN.len()];
        log.read_exact(&mut sign)?;
        if &sign != layout::SIGN {
            anyhow::bail!("not is sftrace log: {:?}", sign);
        }
    }

    let metadata: layout::Metadata = cbor4ii::serde::from_reader(&mut log)?;
    let pid = metadata.pid.try_into().context("bad pid")?;

    let sympath = options.symbol.as_ref().unwrap_or(&metadata.shlib_path);

    let loader = addr2line::Loader::new(sympath)
        .map_err(|err| anyhow::format_err!("parse symbol failed: {:?}", err))?;
    let loader = Addr2Line::new(loader);

    let output = fs::File::create(&options.output)?;
    let mut output = flate2::write::GzEncoder::new(output, flate2::Compression::fast());

    let mut state = State {
        metadata: &metadata,
        loader: &loader,
        process_id: pid,
        stack: HashMap::new()
    };
    let mut packet = PacketWriter::default();

    while !log.fill_buf()?.is_empty() {
        let event: layout::Event = cbor4ii::serde::from_reader(&mut log)?;

        let maybe_addr = match event.kind {
            layout::Kind::ENTRY => {
                let addr = event.child_ip - metadata.shlib_base;
                state.stack.entry(event.tid).or_default().push(addr);
                Some(addr)
            },
            layout::Kind::EXIT | layout::Kind::TAIL_CALL => {
                let mut is_empty = false;

                let maybe_addr = state.stack.get_mut(&event.tid)
                    .and_then(|stack| {
                        let last = stack.pop();
                        is_empty = stack.is_empty();
                        last
                    });

                if maybe_addr.is_none() {
                    eprintln!("missing entry event: {:?}", event);
                }

                if is_empty {
                    state.stack.remove(&event.tid);
                }

                maybe_addr
            },
            _ => None,
        };

        if let Some(addr) = maybe_addr {
            packet.push(&mut state, &event, addr);
        }

        if packet.trace.packet.len() > 128 {
            packet.flush_to(&mut output)?;
        }
    }

    packet.flush_to(&mut output)?;
    output.flush()?;

    Ok(())    
}

fn extract(options: &ExtractCommand) -> anyhow::Result<()> {
    use std::fs;
    use std::ffi::OsStr;
    use object::{ Object, ObjectSymbol };
    use rayon::prelude::*;
    use zerocopy::IntoBytes;

    let objfd = fs::File::open(&options.path)?;
    let objbuf = unsafe { memmap2::Mmap::map(&objfd)? };
    let obj = object::File::parse(&*objbuf)?;

    if let Some(rlibs) = options.rlibs.as_ref() {
        let obj = &obj;
        
        let mut map = glob::glob(rlibs)?
            .filter_map(Result::ok)
            .filter(|entry| entry.extension() == Some(OsStr::new("rlib")))
            .par_bridge()
            .filter_map(|entry| {
                eprintln!("load {:?}", entry);

                fs::File::open(&entry).ok()
            })
            .map(|fd| {
                let buf = unsafe { memmap2::Mmap::map(&fd).unwrap() };
                let rlib = object::read::archive::ArchiveFile::parse(&*buf).unwrap();
                let syms = rlib.symbols().unwrap();

                syms.into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .par_bridge()
                    .filter_map(|sym| {
                        obj.symbol_by_name_bytes(sym.name())
                            .filter(|sym| matches!(sym.kind(), object::SymbolKind::Text))
                            .filter(|sym| sym.is_definition())
                            .map(|sym| sym.address())
                    })
                    .collect::<Vec<u64>>()
            })
            .reduce(Vec::new, |mut sum, mut next| {
                sum.append(&mut next);
                sum
            });
        map.par_sort();
        map.dedup();

        println!("done {:?}", map.len());

        let mut output = fs::File::create(&options.output)?;
        let hash = obj.build_id()
            .ok()
            .flatten()
            .map(layout::FilterMap::build_id_hash)
            .unwrap_or_default();
        output.write_all(&hash.to_ne_bytes())?;
        output.write_all(map.as_bytes())?;
    }

    Ok(())   
}

struct State<'g> {
    #[allow(dead_code)]
    metadata: &'g layout::Metadata,
    loader: &'g Addr2Line,
    process_id: i32,
    stack: HashMap<i32, Vec<u64>>,
}

struct Addr2Line {
    loader: addr2line::Loader,
    cache: RefCell<HashMap<u64, Option<Frame>>>
}

#[derive(Clone)]
struct Frame {
    name: String,
    file: Option<String>,
    line: Option<u32>
}

#[derive(Default)]
struct PacketWriter {
    threads: HashSet<i32>,
    addrmap: HashMap<u64, (Option<u64>, Option<u64>)>,
    event_names: HashMap<String, u64>,
    source_locations: HashMap<(String, Option<u32>), u64>,
    trace: Trace,
}

impl Addr2Line {
    fn new(loader: addr2line::Loader) -> Self {
        Addr2Line {
            loader,
            cache: RefCell::new(HashMap::new())
        }
    }

    fn lookup(&self, addr: u64) -> Option<Frame> {
        let mut cache = self.cache.borrow_mut();

        match cache.entry(addr) {
            hash_map::Entry::Occupied(entry) => entry.get().clone(),
            hash_map::Entry::Vacant(entry) => {
                let frame = self.loader.find_frames(addr)
                    .ok()
                    .and_then(|mut iter| iter.next().ok())
                    .flatten()
                    .map(|frame| Frame {
                        name: frame.function
                            .and_then(|name| name.demangle()
                                .map(|name| name.into_owned())
                                .ok()
                            )
                            .unwrap_or_else(|| "unknown".into()),
                        file: frame.location
                            .as_ref()
                            .and_then(|loc| loc.file)
                            .map(|file| file.to_owned()),
                        line: frame.location.as_ref().and_then(|loc| loc.line),
                    });
                entry.insert(frame).clone()
            }
        }
    }
}

impl PacketWriter {
    fn process_uuid(&mut self, global_state: &State) -> u64 {
        let pid = global_state.process_id;
        
        if self.trace.packet.is_empty() {
            let mut packet = micromegas_perfetto::writer::new_trace_packet();
            let mut track_desc = micromegas_perfetto::writer::new_track_descriptor(pid as u64);
            track_desc.process = Some(micromegas_perfetto::protos::ProcessDescriptor {
                pid: Some(pid),
                ..Default::default()
            });
            packet.first_packet_on_sequence = Some(true);
            packet.sequence_flags = Some(3);
            packet.data = Some(trace_packet::Data::TrackDescriptor(track_desc));
            self.trace.packet.push(packet);            
        }

        pid as u64        
    }
    
    fn thread_uuid(&mut self, global_state: &State, event: &layout::Event) -> u64 {
        let pid = self.process_uuid(global_state);
        let tid = event.tid;
        
        if !self.threads.insert(tid) {
            let mut packet = micromegas_perfetto::writer::new_trace_packet();
            let mut track_desc = micromegas_perfetto::writer::new_track_descriptor(tid as u64);
            track_desc.parent_uuid = Some(pid);
            track_desc.thread = Some(micromegas_perfetto::protos::ThreadDescriptor {
                pid: Some(global_state.process_id),
                tid: Some(tid),
                ..Default::default()
            });
            packet.data = Some(trace_packet::Data::TrackDescriptor(track_desc));
            self.trace.packet.push(packet);
        }

        tid as u64
    }

    fn frame_info(&mut self, global_state: &State, packet: &mut TracePacket, addr: u64)
        -> (Option<u64>, Option<u64>)
    {
        match self.addrmap.entry(addr) {
            hash_map::Entry::Occupied(entry) => return *entry.get(),
            hash_map::Entry::Vacant(entry) => {
                let Some(frame) = global_state.loader.lookup(addr)
                    else {
                        return *entry.insert((None, None));
                    };

                let interned_data = packet.interned_data.get_or_insert_default();

                let next_name_id = self.event_names.len() + 1;
                let name_id = match self.event_names.entry(frame.name.clone()) {
                    hash_map::Entry::Occupied(entry) => *entry.get(),
                    hash_map::Entry::Vacant(entry) => {
                        interned_data.event_names.push(EventName {
                            iid: Some(next_name_id as u64),
                            name: Some(entry.key().clone())
                        });

                        *entry.insert(next_name_id as u64)
                    },
                };

                let loc_id = if let Some(file) = frame.file {
                    let next_loc_id = self.source_locations.len() + 1;
                    let loc_id = match self.source_locations.entry((file, frame.line)) {
                        hash_map::Entry::Occupied(entry) => *entry.get(),
                        hash_map::Entry::Vacant(entry) => {
                            let (file, line) = entry.key().clone();
                            interned_data.source_locations.push(SourceLocation {
                                iid: Some(next_loc_id as u64),
                                file_name: Some(file),
                                function_name: Some(frame.name),
                                line_number: line
                            });

                            *entry.insert(next_name_id as u64)
                        },
                    };

                    Some(loc_id)
                } else {
                    None
                };

                entry.insert((Some(name_id), loc_id)).clone()
            }
        }
    }
    
    fn push(&mut self, state: &mut State, event: &layout::Event, addr: u64) {
        let thread_uuid = self.thread_uuid(state, event);

        let mut packet = micromegas_perfetto::writer::new_trace_packet();
        let mut track_event = micromegas_perfetto::writer::new_track_event();
        packet.timestamp = Some(event.time);
        track_event.track_uuid = Some(thread_uuid);

        match event.kind {
            layout::Kind::ENTRY => {
                track_event.r#type = Some(track_event::Type::SliceBegin.into());
                let (name_id, loc_id) = self.frame_info(state, &mut packet, addr);
                track_event.name_field = name_id.map(track_event::NameField::NameIid);
                track_event.source_location_field = loc_id.map(track_event::SourceLocationField::SourceLocationIid);
            },
            layout::Kind::EXIT | layout::Kind::TAIL_CALL => {
                track_event.r#type = Some(track_event::Type::SliceEnd.into());
                let (name_id, loc_id) = self.frame_info(state, &mut packet, addr);
                track_event.name_field = name_id.map(track_event::NameField::NameIid);
                track_event.source_location_field = loc_id.map(track_event::SourceLocationField::SourceLocationIid);
            },
            _ => ()
        }

        packet.data = Some(trace_packet::Data::TrackEvent(track_event));
        self.trace.packet.push(packet);
    }

    fn flush_to<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        if self.trace.packet.is_empty() {
            return Ok(());
        }
        
        let buf = self.trace.encode_to_vec();
        writer.write_all(&buf)?;
        self.trace.packet.clear();
        self.threads.clear();
        self.addrmap.clear();
        self.event_names.clear();
        self.source_locations.clear();
        Ok(())
    }
}
