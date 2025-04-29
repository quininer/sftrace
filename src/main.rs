mod layout;

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::collections::{ hash_map, HashMap, HashSet };
use addr2line::fallible_iterator::FallibleIterator;
use parking_lot::{ Mutex, RwLock };
use anyhow::Context;
use argh::FromArgs;
use zerocopy::FromBytes;
use rayon::iter::{ParallelBridge, ParallelIterator};
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
    let log = unsafe {
        memmap2::Mmap::map(&log)?
    };

    let loader = addr2line::Loader::new(&options.symbol)
        .map_err(|err| anyhow::format_err!("parse symbol failed: {:?}", err))?;
    let loader = Addr2Line::new(loader);

    let log = layout::LogFile::ref_from_bytes(log.as_ref())
        .ok()
        .context("log parse failed")?;
    if log.metadata.sign != *layout::SIGN {
        anyhow::bail!("not is sftrace log: {:?}", log.metadata.sign);
    }
    let pid = log.metadata.pid.get().try_into().context("bad pid")?;

    let state = GlobalState {
        metadata: &log.metadata,
        loader: &loader,
        process_id: pid,
        thread_stacks: Default::default()
    };

    let output = fs::File::create(&options.output)?;
    let output = flate2::write::GzEncoder::new(output, flate2::Compression::fast());
    let output = Mutex::new(output);

    let last = &log.events;

    // let iter = log.events.chunks_exact(std::mem::size_of::<layout::Event>() * 1024);
    // let last = iter.remainder();

    // iter.par_bridge()
    //     .try_for_each(|chunk| process_chunk(&state, chunk, &output))?;
    if !last.is_empty() {
        process_chunk(&state, last, &output)?;
    }

    let mut output = output.into_inner();
    output.flush()?;

    Ok(())    
}

struct GlobalState<'g> {
    #[allow(dead_code)]
    metadata: &'g layout::Metadata,
    loader: &'g Addr2Line,
    process_id: i32,
    thread_stacks: RwLock<HashMap<i32, Arc<Mutex<Vec<u64>>>>>
}

struct Addr2Line {
    loader: Mutex<addr2line::Loader>,
    cache: RwLock<HashMap<u64, Frame>>
}

#[derive(Clone)]
struct Frame {
    name: String,
    file: Option<String>,
    line: Option<u32>
}

#[derive(Default)]
struct PacketState {
    threads: HashSet<i32>,
    addrmap: HashMap<u64, (Option<u64>, Option<u64>)>,
    event_names: HashMap<String, u64>,
    source_locations: HashMap<(String, Option<u32>), u64>,
    stack: Vec<u64>,
    trace: Trace,
}

impl Addr2Line {
    fn new(loader: addr2line::Loader) -> Self {
        Addr2Line {
            loader: Mutex::new(loader),
            cache: RwLock::new(HashMap::new())
        }
    }

    fn lookup(&self, addr: u64) -> Option<Frame> {
        let cache = self.cache.upgradable_read();
        if let Some(frame) = cache.get(&addr) {
            return Some(frame.clone());
        }

        let loader = self.loader.lock();
        let frame = loader.find_frames(addr)
            .ok()?
            .next()
            .ok()??;
        let frame = Frame {
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
        };
        let mut cache = parking_lot::RwLockUpgradableReadGuard::upgrade(cache);
        cache.insert(addr, frame.clone());

        Some(frame)
    }
}

impl PacketState {
    fn process_uuid(&mut self, global_state: &GlobalState) -> u64 {
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
    
    fn thread_uuid(&mut self, global_state: &GlobalState, event: &layout::Event) -> u64 {
        let pid = self.process_uuid(global_state);
        let tid = event.tid.get();
        
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

    fn frame_info(&mut self, global_state: &GlobalState, packet: &mut TracePacket, addr: u64)
        -> (Option<u64>, Option<u64>)
    {
        match self.addrmap.entry(addr) {
            hash_map::Entry::Occupied(entry) => return *entry.get(),
            hash_map::Entry::Vacant(entry) => {
                let Some(frame) = global_state.loader.lookup(addr - global_state.metadata.shlib_base.get())
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
    
    fn push(&mut self, global_state: &GlobalState, event: &layout::Event) {
        let thread_uuid = self.thread_uuid(global_state, event);

        let mut packet = micromegas_perfetto::writer::new_trace_packet();
        let mut track_event = micromegas_perfetto::writer::new_track_event();
        packet.timestamp = Some(event.time.get());
        track_event.track_uuid = Some(thread_uuid);

        match event.kind {
            layout::Kind::ENTRY => {
                track_event.r#type = Some(track_event::Type::SliceBegin.into());
                let addr = event.child_ip.get();
                self.stack.push(addr);
                let (name_id, loc_id) = self.frame_info(global_state, &mut packet, addr);
                track_event.name_field = name_id.map(track_event::NameField::NameIid);
                track_event.source_location_field = loc_id.map(track_event::SourceLocationField::SourceLocationIid);
            },
            layout::Kind::EXIT => {
                track_event.r#type = Some(track_event::Type::SliceEnd.into());
                // FIXME cross chunk stack
                if let Some(addr) = self.stack.pop() {
                    let (name_id, loc_id) = self.frame_info(global_state, &mut packet, addr);
                    track_event.name_field = name_id.map(track_event::NameField::NameIid);
                    track_event.source_location_field = loc_id.map(track_event::SourceLocationField::SourceLocationIid);
                }
            },
            _ => ()
        }

        packet.data = Some(trace_packet::Data::TrackEvent(track_event));
        self.trace.packet.push(packet);
    }
}

fn process_chunk<W: Write>(global_state: &GlobalState, chunk: &[layout::Event], output: &Mutex<W>) -> anyhow::Result<()> {
    let mut state = PacketState::default();

    for event in chunk {
        state.push(global_state, event);    
    }

    let trace = std::mem::take(&mut state.trace);
    drop(state);
    let buf = trace.encode_to_vec();
    let mut output = output.lock();
    output.write_all(&buf)?;

    Ok(())
}
