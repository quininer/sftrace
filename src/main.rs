mod layout;

use std::{fs, io};
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::cell::RefCell;
use std::collections::{ hash_map, HashMap, HashSet };
use anyhow::Context;
use argh::FromArgs;
use object::{Object, ObjectSection};
use prost::Message;
use micromegas_perfetto::protos::{ Trace, TracePacket, EventName, SourceLocation, trace_packet, track_event };

/// sftrace tools
#[derive(FromArgs)]
struct Options {
    /// sftrace trace path
    #[argh(positional)]
    path: PathBuf,

    /// debug symbol path
    #[argh(option, short = 's')]
    symbol: PathBuf,

    /// chrome-trace output path
    #[argh(option, short = 'o')]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    let log = fs::File::open(&options.path)?;
    let mut log = io::BufReader::new(log);

    let loader = addr2line::Loader::new(&options.symbol)
        .map_err(|err| anyhow::format_err!("parse symbol failed: {:?}", err))?;
    let loader = Addr2Line::new(loader);

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

    let func_map = {
        let symfd = fs::File::open(&options.symbol)?;
        let symbuf = unsafe { memmap2::Mmap::map(&symfd)? };
        let obj = object::File::parse(&*symbuf)?;    

        if let Ok(Some(build_id)) = obj.build_id() {
            if metadata.shlibid != build_id {
                anyhow::bail!("build id does not match: {:?} vs {:?}", metadata.shlibid, build_id);
            }
        }

        FunctionEntryMap::from_obj(&obj, metadata.shlib_base)?
    };

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

        match event.kind {
            layout::Kind::ENTRY => {
                let stack = state.stack.entry(event.tid).or_default();
                stack.push(event.child_ip);
            },
            layout::Kind::EXIT => {
                let mut is_empty = false;
                if let Some(stack) = state.stack.get_mut(&event.tid) {
                    stack.pop();

                    while let Some(last) = stack.last() {
                        let entry_flag = func_map.0.get(&last).unwrap();
                        if entry_flag.contains(FunctionEntry::TAIL_CALL) {
                            stack.pop();
                        } else {
                            break
                        }
                    }

                    is_empty = stack.is_empty();
                } else {
                    eprintln!("missing entry event: {:?}", event);
                }

                if is_empty {
                    state.stack.remove(&event.tid);
                }
            },
            _ => (),
        }
        
        packet.push(&mut state, &event);

        if packet.trace.packet.len() == 1024 {
            packet.flush_to(&mut output)?;
        }
    }

    packet.flush_to(&mut output)?;
    output.flush()?;

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

struct FunctionEntryMap(HashMap<u64, FunctionEntry>);

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
    struct FunctionEntry: u8 {
        const ENTRY     = 0b00;
        const EXIT      = 0b01;
        const TAIL_CALL = 0b10;
    }
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

impl FunctionEntryMap {
    pub fn from_obj(obj: &object::File<'_>, base: u64) -> anyhow::Result<Self> {
        use zerocopy::FromBytes;
        
        let xray_section = obj.section_by_name("xray_instr_map").context("not found xray_instr_map section")?;
        let buf = xray_section.uncompressed_data()?;
        let base: usize = base.try_into()?;

        let entry_map = <[layout::XRayFunctionEntry]>::ref_from_bytes(buf.as_ref())
            .ok()
            .context("xray section map parse failed")?;
        let section_offset: usize = xray_section.address().try_into().unwrap();
        let mut output = HashMap::new();

        for (_addr, func, entry) in layout::XRayInstrMap(entry_map)
            .iter(base, section_offset)
        {
            let kind = match entry.kind {
                0 => FunctionEntry::ENTRY,
                1 => FunctionEntry::EXIT,
                2 => FunctionEntry::TAIL_CALL,
                _ => FunctionEntry::ENTRY,
            };
            
            *output.entry(func as u64).or_insert(kind) |= kind;
        }

        output.shrink_to_fit();
        Ok(FunctionEntryMap(output))
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
                let Some(frame) = global_state.loader.lookup(addr - global_state.metadata.shlib_base)
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
    
    fn push(&mut self, state: &mut State, event: &layout::Event) {
        let thread_uuid = self.thread_uuid(state, event);

        let mut packet = micromegas_perfetto::writer::new_trace_packet();
        let mut track_event = micromegas_perfetto::writer::new_track_event();
        packet.timestamp = Some(event.time);
        track_event.track_uuid = Some(thread_uuid);

        match event.kind {
            layout::Kind::ENTRY => {
                track_event.r#type = Some(track_event::Type::SliceBegin.into());
                let addr = event.child_ip;
                state.stack.entry(event.tid).or_default().push(addr);
                let (name_id, loc_id) = self.frame_info(state, &mut packet, addr);
                track_event.name_field = name_id.map(track_event::NameField::NameIid);
                track_event.source_location_field = loc_id.map(track_event::SourceLocationField::SourceLocationIid);
            },
            layout::Kind::EXIT => {
                track_event.r#type = Some(track_event::Type::SliceEnd.into());
                if let Some(addr) = state.stack.get_mut(&event.tid).and_then(|stack| stack.pop()) {
                    let (name_id, loc_id) = self.frame_info(state, &mut packet, addr);
                    track_event.name_field = name_id.map(track_event::NameField::NameIid);
                    track_event.source_location_field = loc_id.map(track_event::SourceLocationField::SourceLocationIid);
                } else {
                    eprintln!("missing entry event: {:?}", event);
                }
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
