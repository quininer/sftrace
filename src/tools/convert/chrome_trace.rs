use crate::layout;
use crate::util::ArgsData;
use micromegas_perfetto::protos::{
    DebugAnnotation, EventName, SourceLocation, Trace, TracePacket, debug_annotation, trace_packet,
    track_event,
};
use prost::Message;
use std::collections::{HashMap, HashSet, hash_map};
use std::io::{BufRead, Write};
use std::path::Path;
use std::{fs, io};
use super::State;

#[derive(Default)]
pub struct PacketWriter {
    threads: HashSet<u32>,
    addrmap: HashMap<u64, (Option<u64>, Option<u64>)>,
    event_names: HashMap<String, u64>,
    source_locations: HashMap<(String, Option<u32>), u64>,
    trace: Trace,
}

impl PacketWriter {
    pub fn convert(&mut self, mut log: &mut io::BufReader<fs::File>, state: &mut State, output: &Path)
    -> anyhow::Result<()>
    {
        let output = fs::File::create(output)?;
        let mut output = flate2::write::GzEncoder::new(output, flate2::Compression::fast());
                
        while !log.fill_buf()?.is_empty() {
            let event: layout::Event<ArgsData, ArgsData, layout::AllocEvent> =
                cbor4ii::serde::from_reader(&mut log)?;

            match event.kind {
                layout::Kind::ENTRY => {
                    let func_id = event.func_id;
                    state.stack.entry(event.tid).or_default().push(func_id);
                    self.push_call(state, &event, func_id);
                }
                layout::Kind::EXIT | layout::Kind::TAIL_CALL => {
                    let mut has_entry = false;
                    let mut is_empty = false;

                    if let Some(stack) = state.stack.get_mut(&event.tid) {
                        if let Some(entry_func_id) = stack.pop() {
                            has_entry = true;

                            let entry_func = state
                                .entry_map
                                .get(state.section_offset, entry_func_id)
                                .function();
                            let exit_func = state
                                .entry_map
                                .get(state.section_offset, event.func_id)
                                .function();

                            if entry_func != exit_func {
                                eprintln!(
                                    "func id does not match: {:?} vs {:?}",
                                    entry_func_id, event.func_id
                                );
                            }
                        }

                        is_empty = stack.is_empty();
                    }

                    if !has_entry {
                        eprintln!("missing entry event: {:?}", event);
                    }

                    if is_empty {
                        state.stack.remove(&event.tid);
                    }

                    self.push_call(state, &event, event.func_id);
                }
                // temp ignore
                layout::Kind::ALLOC
                | layout::Kind::DEALLOC
                | layout::Kind::REALLOC_ALLOC
                | layout::Kind::REALLOC_DEALLOC => (),
                _ => (),
            };

            if self.trace.packet.len() > 128 {
                self.flush_to(&mut output)?;
            }
        }

        self.flush_to(&mut output)?;
        output.flush()?;

        Ok(())
    }
    
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

    fn thread_uuid(
        &mut self,
        global_state: &State,
        event: &layout::Event<ArgsData, ArgsData, layout::AllocEvent>,
    ) -> u64 {
        let pid = self.process_uuid(global_state);
        let tid = event.tid;

        if !self.threads.insert(tid) {
            let mut packet = micromegas_perfetto::writer::new_trace_packet();
            let mut track_desc = micromegas_perfetto::writer::new_track_descriptor(tid as u64);
            track_desc.parent_uuid = Some(pid);
            track_desc.thread = Some(micromegas_perfetto::protos::ThreadDescriptor {
                pid: Some(global_state.process_id),
                tid: Some(tid.try_into().unwrap()),
                ..Default::default()
            });
            packet.data = Some(trace_packet::Data::TrackDescriptor(track_desc));
            self.trace.packet.push(packet);
        }

        tid as u64
    }

    fn frame_info(
        &mut self,
        global_state: &State,
        packet: &mut TracePacket,
        addr: u64,
    ) -> (Option<u64>, Option<u64>) {
        match self.addrmap.entry(addr) {
            hash_map::Entry::Occupied(entry) => *entry.get(),
            hash_map::Entry::Vacant(entry) => {
                let Some(frame) = global_state.loader.lookup(addr) else {
                    return *entry.insert((None, None));
                };

                let interned_data = packet.interned_data.get_or_insert_default();

                let next_name_id = self.event_names.len() + 1;
                let name_id = match self.event_names.entry(frame.name.clone()) {
                    hash_map::Entry::Occupied(entry) => *entry.get(),
                    hash_map::Entry::Vacant(entry) => {
                        interned_data.event_names.push(EventName {
                            iid: Some(next_name_id as u64),
                            name: Some(entry.key().clone()),
                        });

                        *entry.insert(next_name_id as u64)
                    }
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
                                line_number: line,
                            });

                            *entry.insert(next_loc_id as u64)
                        }
                    };

                    Some(loc_id)
                } else {
                    None
                };

                *entry.insert((Some(name_id), loc_id))
            }
        }
    }

    fn push_call(
        &mut self,
        state: &mut State,
        event: &layout::Event<ArgsData, ArgsData, layout::AllocEvent>,
        func_id: u32,
    ) {
        let thread_uuid = self.thread_uuid(state, event);
        let entry = state.entry_map.get(state.section_offset, func_id);
        let addr = entry.function();

        let mut packet = micromegas_perfetto::writer::new_trace_packet();
        let mut track_event = micromegas_perfetto::writer::new_track_event();
        packet.timestamp = Some(event.time);
        track_event.track_uuid = Some(thread_uuid);

        match event.kind {
            layout::Kind::ENTRY => {
                track_event.r#type = Some(track_event::Type::SliceBegin.into());
                let (name_id, loc_id) = self.frame_info(state, &mut packet, addr);
                track_event.name_field = name_id.map(track_event::NameField::NameIid);
                track_event.source_location_field =
                    loc_id.map(track_event::SourceLocationField::SourceLocationIid);
                track_event.debug_annotations = event
                    .args
                    .as_ref()
                    .map(|data| to_debug_anno("args", data))
                    .into_iter()
                    .collect();
            }
            layout::Kind::EXIT | layout::Kind::TAIL_CALL => {
                track_event.r#type = Some(track_event::Type::SliceEnd.into());
                let (name_id, loc_id) = self.frame_info(state, &mut packet, addr);
                track_event.name_field = name_id.map(track_event::NameField::NameIid);
                track_event.source_location_field =
                    loc_id.map(track_event::SourceLocationField::SourceLocationIid);
                track_event.debug_annotations = event
                    .return_value
                    .as_ref()
                    .map(|data| to_debug_anno("return_value", data))
                    .into_iter()
                    .collect();
            }
            _ => unreachable!(),
        }

        packet.data = Some(trace_packet::Data::TrackEvent(track_event));
        self.trace.packet.push(packet);
    }

    // fn push_alloc_event(
    //     &mut self,
    //     state: &mut State,
    //     event: &layout::Event<Data, Data, layout::AllocEvent>
    // ) {
    //     use micromegas_perfetto::protos::{ StreamingAllocation, StreamingFree };

    //     let Some(alloc_event) = event.alloc_event.as_ref()
    //         else {
    //             println!("miss alloc event data");
    //             return
    //         };

    //     let thread_uuid = self.thread_uuid(state, event);

    //     let mut packet = micromegas_perfetto::writer::new_trace_packet();
    //     let mut track_event = micromegas_perfetto::writer::new_track_event();
    //     packet.timestamp = Some(event.time);
    //     track_event.track_uuid = Some(thread_uuid);
    //     track_event.r#type = Some(track_event::Type::Instant.into());

    //     dbg!(&alloc_event);

    //     match event.kind {
    //         layout::Kind::ALLOC => {
    //             let mut data = StreamingAllocation::default();
    //             data.address = vec![alloc_event.new_ptr];
    //             data.size = vec![alloc_event.new_size];
    //             packet.data = Some(trace_packet::Data::StreamingAllocation(data));
    //             self.trace.packet.push(packet);
    //         },
    //         layout::Kind::DEALLOC => {
    //             let mut data = StreamingFree::default();
    //             data.address = vec![alloc_event.old_ptr];
    //             packet.data = Some(trace_packet::Data::StreamingFree(data));
    //             self.trace.packet.push(packet);
    //         },
    //         layout::Kind::REALLOC => {
    //             let mut data = StreamingFree::default();
    //             data.address = vec![alloc_event.old_ptr];
    //             packet.data = Some(trace_packet::Data::StreamingFree(data));
    //             self.trace.packet.push(packet.clone());

    //             {
    //                 let mut data = StreamingAllocation::default();
    //                 data.address = vec![alloc_event.new_ptr];
    //                 data.size = vec![alloc_event.new_size];
    //                 packet.data = Some(trace_packet::Data::StreamingAllocation(data));
    //                 self.trace.packet.push(packet);
    //             }
    //         },
    //         _ => unreachable!()
    //     }
    // }

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

#[allow(clippy::field_reassign_with_default)]
fn to_debug_anno(name: &str, data: &ArgsData) -> DebugAnnotation {
    let mut anno = DebugAnnotation::default();
    anno.name_field = Some(debug_annotation::NameField::Name(name.into()));
    anno.dict_entries = data
        .0
        .vec
        .iter()
        .map(|(k, v)| {
            let v = *v;
            let mut anno = DebugAnnotation::default();
            anno.name_field = Some(debug_annotation::NameField::Name(k.into()));

            match v.try_into() {
                Ok(v) => anno.value = Some(debug_annotation::Value::UintValue(v)),
                Err(_) => {
                    let x = v as u64;
                    let y = (v >> 64) as u64;

                    let x = {
                        let mut anno = DebugAnnotation::default();
                        anno.value = Some(debug_annotation::Value::UintValue(x));
                        anno
                    };
                    let y = {
                        let mut anno = DebugAnnotation::default();
                        anno.value = Some(debug_annotation::Value::UintValue(y));
                        anno
                    };
                    anno.array_values = vec![x, y];
                }
            }

            anno
        })
        .collect();
    anno
}
