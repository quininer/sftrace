use std::fs;
use std::ops::Range;
use std::io::{ self, Read, BufRead };
use std::path::PathBuf;
use std::collections::HashMap;
use argh::FromArgs;
use anyhow::Context;
use zerocopy::FromBytes;
use object::{Object, ObjectSection, ObjectSymbol};
use serde::de::IgnoredAny;
use crate::layout;

/// Analyzer command
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "analyzer")]
pub struct SubCommand {
    /// sftrace trace path
    #[argh(positional)]
    path: PathBuf,

    /// debug symbol path
    #[argh(option, short = 's')]
    symbol: Option<PathBuf>,

    /// milestone symbol
    #[argh(option)]
    milestone: String,
}

impl SubCommand {
    pub fn exec(&self) -> anyhow::Result<()> {
        let log = fs::File::open(&self.path)?;
        let mut log = io::BufReader::new(log);

        // check sign
        {
            let mut sign = [0; layout::SIGN_TRACE.len()];
            log.read_exact(&mut sign)?;
            if &sign != layout::SIGN_TRACE {
                anyhow::bail!("not is sftrace log: {:?}", sign);
            }
        }

        let metadata: layout::Metadata = cbor4ii::serde::from_reader(&mut log)?;
        
        let sympath = self.symbol.as_ref().unwrap_or(&metadata.shlib_path);
        let symfd = fs::File::open(&sympath)?;
        let symbuf = unsafe { memmap2::Mmap::map(&symfd)? };
        let symobj = object::File::parse(&*symbuf)?;
        let xray_section = symobj.section_by_name("xray_instr_map")
            .context("not found xray_instr_map section")?;
        let xray_buf = xray_section.uncompressed_data()?;

        let entry_map = <[layout::XRayFunctionEntry]>::ref_from_bytes(xray_buf.as_ref())
            .map_err(|_| anyhow::format_err!("xray_instr_map parse failed"))?;
        let section_offset: usize = xray_section.address().try_into()?;        
        let entry_map = layout::XRayInstrMap(entry_map);

        let mut memory_analyzer = {
            let mileston_sym = symobj.symbol_by_name(&self.milestone)
                .context("not found milestone symbol")?;
            let (mileston_func_id, ..) = entry_map.iter(section_offset)
                .find(|(_, _, func_addr, _)| (*func_addr as u64) == mileston_sym.address())
                .context("not found milestone xray entry")?;
            MemoryAnalyzer::new(mileston_func_id as u32)
        };

        while !log.fill_buf()?.is_empty() {
            let event: layout::Event<IgnoredAny, IgnoredAny, layout::AllocEvent> =
                cbor4ii::serde::from_reader(&mut log)?;

            memory_analyzer.eat(&event)?;
        }

        drop(log);

        let result = memory_analyzer.analyze();

        for stage in &result.list {
            println!("{:?}", stage.len());
        }

        Ok(())        
    }
}

struct MemoryAnalyzer {
    milestone_func_id: u32,
    milestones: Vec<u64>,
    threads: HashMap<i32, Vec<u32>>,
    stacklist: Vec<u32>,
    alloc_event: Vec<AllocEvent>,
}

struct AllocEvent {
    kind: layout::Kind,
    tid: i32,
    time: u64,
    ptr: u64,
    size: u64,
    stackrange: Range<usize>,
}

#[derive(Default)]
struct MemoryResult {
    list: Vec<Vec<usize>>
}

impl MemoryAnalyzer {
    fn new(milestone_func_id: u32) -> MemoryAnalyzer {
        MemoryAnalyzer {
            milestone_func_id,
            milestones: Vec::new(),
            threads: Default::default(),
            stacklist: Default::default(),
            alloc_event: Default::default()
        }
    }
    
    fn eat(&mut self, event: &layout::Event<IgnoredAny, IgnoredAny, layout::AllocEvent>)
        -> anyhow::Result<()>
    {
        match event.kind {
            layout::Kind::ENTRY => {
                self.threads.entry(event.tid).or_default().push(event.func_id);
                if event.func_id == self.milestone_func_id {
                    self.milestones.push(event.time);
                }
            },
            layout::Kind::EXIT | layout::Kind::TAIL_CALL => {
                self.threads.entry(event.tid).or_default().pop();
            },
            layout::Kind::ALLOC
            | layout::Kind::DEALLOC
            | layout::Kind::REALLOC => {
                let alloc_event = event.alloc_event.as_ref().unwrap();
                
                let stack = self.threads.get(&event.tid)
                    .map(|stack| stack.as_slice())
                    .unwrap_or_default();
                
                let stackrange = if self.stacklist.ends_with(stack) {
                    let start = self.stacklist.len() - stack.len();
                    let end = self.stacklist.len();
                    start..end
                } else {
                    let start = self.stacklist.len();
                    self.stacklist.extend_from_slice(stack);
                    let end = self.stacklist.len();
                    start..end
                };

                match event.kind {
                    layout::Kind::ALLOC => self.alloc_event.push(AllocEvent {
                        kind: event.kind,
                        tid: event.tid,
                        time: event.time,
                        ptr: alloc_event.new_ptr,
                        size: alloc_event.new_size,
                        stackrange
                    }),
                    layout::Kind::DEALLOC => self.alloc_event.push(AllocEvent {
                        kind: event.kind,
                        tid: event.tid,
                        time: event.time,
                        ptr: alloc_event.old_ptr,
                        size: alloc_event.old_size,
                        stackrange
                    }),
                    layout::Kind::REALLOC => if alloc_event.new_ptr == alloc_event.old_ptr {
                        self.alloc_event.push(AllocEvent {
                            kind: event.kind,
                            tid: event.tid,
                            time: event.time,
                            ptr: alloc_event.new_ptr,
                            size: alloc_event.new_ptr,
                            stackrange
                        });
                    } else {
                        self.alloc_event.push(AllocEvent {
                            kind: layout::Kind::DEALLOC,
                            tid: event.tid,
                            time: event.time,
                            ptr: alloc_event.old_ptr,
                            size: alloc_event.old_ptr,
                            stackrange: stackrange.clone()
                        });
                        self.alloc_event.push(AllocEvent {
                            kind: layout::Kind::ALLOC,
                            tid: event.tid,
                            time: event.time,
                            ptr: alloc_event.new_ptr,
                            size: alloc_event.new_ptr,
                            stackrange
                        });
                    },
                    _ => unreachable!()
                }
            },
            _ => unreachable!()
        }

        Ok(())
    }

    fn analyze(&mut self) -> MemoryResult {
        use std::collections::hash_map;
        use rayon::prelude::*;
        
        self.threads = HashMap::new();

        self.milestones.sort_by_key(|&t| std::cmp::Reverse(t));
        self.alloc_event.par_sort_by_key(|ev| ev.time);

        let mut milestones = Vec::new();
        let mut next = self.alloc_event.as_slice();

        while !next.is_empty() {
            if let Some(point) = self.milestones.pop() {
                let mid = next.partition_point(|ev| ev.time <= point);
                let (x, y) = next.split_at(mid);
                milestones.push(x);
                next = y;
            } else {
                milestones.push(next);
                next = &[];
            }
        }

        let list = milestones
            .into_iter()
            .scan(0, |st, next| {
                let idx = *st;
                *st += next.len();
                Some((idx, next))
            })
            .par_bridge()
            .map(|(base, events)| {
                let mut ptrmap: HashMap<u64, Vec<_>> = HashMap::new();
                let mut keep = Vec::new();

                for (idx, ev) in events.iter().enumerate() {
                    let idx = base + idx;

                    match ev.kind {
                        layout::Kind::ALLOC => {
                            ptrmap.entry(ev.ptr).or_default().push(idx);
                        },
                        layout::Kind::DEALLOC => {
                            if ptrmap.remove(&ev.ptr).is_none() {
                                keep.push(idx);
                            }
                        },
                        layout::Kind::REALLOC => {
                            match ptrmap.entry(ev.ptr) {
                                hash_map::Entry::Occupied(mut entry) => entry.get_mut().push(idx),
                                hash_map::Entry::Vacant(_) => keep.push(idx)
                            }
                        },
                        _ => unreachable!()
                    }
                }

                keep.extend(ptrmap.into_values().flatten());
                keep.sort_by_key(|&idx| self.alloc_event[idx].time);
                keep
            })
            .collect::<Vec<_>>();

        MemoryResult { list }
    }
}
