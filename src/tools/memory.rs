use std::fs;
use std::ops::Range;
use std::io::{ self, BufRead, Read, Write };
use std::path::{ Path, PathBuf };
use std::collections::HashMap;
use std::time::Duration;
use argh::FromArgs;
use anyhow::Context;
use indexmap::IndexMap;
use zerocopy::FromBytes;
use object::{Object, ObjectSection, ObjectSymbol};
use serde::de::IgnoredAny;
use crate::layout;

/// Memory Analyze command
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "memory")]
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

    /// interactive mode
    #[argh(switch)]
    interactive: bool,

    /// leak flamegraph
    #[argh(option)]
    flamegraph: Option<PathBuf>,

    /// alloc event plot
    #[argh(option)]
    plot: Option<PathBuf>,

    /// fold stage (plot)
    #[argh(switch)]
    fold: bool,

    /// select stage (flamegraph)
    #[argh(option)]
    select: Option<String>
}

macro_rules! try_ {
    ( $( $token:tt )* ) => {{
        #[allow(unused_mut)]
        let mut b = || {
            $( $token )*
        };
        let result: anyhow::Result<()> = b();
        match result {
            Ok(()) => (),
            Err(err) => eprintln!("{:?}", err)
        }
    }};
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
        let symfd = fs::File::open(sympath)?;
        let symbuf = unsafe { memmap2::Mmap::map(&symfd)? };
        let symobj = object::File::parse(&*symbuf)?;
        let xray_section = symobj.section_by_name("xray_instr_map")
            .context("not found xray_instr_map section")?;
        let xray_buf = xray_section.uncompressed_data()?;

        let entry_map = <[layout::XRayFunctionEntry]>::ref_from_bytes(xray_buf.as_ref())
            .map_err(|_| anyhow::format_err!("xray_instr_map parse failed"))?;
        let entry_map = layout::XRayInstrMap(entry_map);

        let mut memory_analyzer = {
            let mileston_sym = symobj.symbol_by_name(&self.milestone)
                .context("not found milestone symbol")?;
            let entry = entry_map.iter(xray_section.address())
                .find(|entry| entry.function() == mileston_sym.address())
                .context("not found milestone xray entry")?;
            MemoryAnalyzer::new(entry.id())
        };

        while !log.fill_buf()?.is_empty() {
            let event: layout::Event<IgnoredAny, IgnoredAny, layout::AllocEvent> =
                cbor4ii::serde::from_reader(&mut log)?;

            memory_analyzer.eat(&event)?;
        }

        drop(log);

        let stage_result = memory_analyzer.split_and_cut();
        let analyze_result = memory_analyzer.analyze(self, &stage_result)?;

        let symbol_table = SymbolTable {
            entry_map,
            section_offset: xray_section.address(),
            symbol_map: symobj.symbol_map()
        };
        

        if let Some(path) = self.flamegraph.as_ref() {
            memory_analyzer.write_flamegraph(
                &symbol_table,
                &stage_result,
                &analyze_result,
                path
            )?;
        }

        if let Some(path) = self.plot.as_ref() {
            memory_analyzer.write_plot(
                self.fold,
                &stage_result,
                &analyze_result,
                path
            )?;
        }

        if !self.interactive {
            return Ok(());
        }

        let mut line = String::new();
        let stdin = io::stdin();

        loop {
            println!();
            
            line.clear();
            stdin.read_line(&mut line)?;

            if line.is_empty() {
                break
            }

            let mut iter = line.split_ascii_whitespace();
            let Some(cmd) = iter.next()
                else { continue };

            match cmd {
                "exit" => break,
                "track" => try_! {
                    let event_id: usize = iter.next()
                        .context("need event id")?
                        .parse()?;
                    let show_stack = iter.next() == Some("--stack");

                    let list = memory_analyzer.track(event_id);
                    for id in list {
                        let ev = &memory_analyzer.alloc_event[id];
                        let kind = kind_to_str(ev.kind);
                        let last_stack = ev.stackrange.clone().last()
                            .filter(|_| show_stack)
                            .map(|stackid| memory_analyzer.stacklist[stackid])
                            .map(|func_id| symbol_table.entry_map.get(symbol_table.section_offset, func_id))
                            .and_then(|entry| symbol_table.symbol_map.get(entry.function()))
                            .map(|name| addr2line::demangle_auto(name.name().into(), None))
                            .unwrap_or_default();
                        println!("{} {}\ttid:{}\tsize:{}\t\t{}", id, kind, ev.tid, ev.size, &last_stack);
                    }
                    Ok(())
                },
                "show" => try_! {
                    let event_id: usize = iter.next()
                        .context("need event id")?
                        .parse()?;
                    let no_stack = iter.next() == Some("--no-stack");
                    memory_analyzer.print_event(&symbol_table, event_id, no_stack)?;
                    Ok(())
                },
                "stage-memory" => try_!{
                    for (stage_idx, stage) in analyze_result.list.iter().enumerate() {
                        println!("{}:\t{:?}", stage_idx, stage.last());
                    }

                    Ok(())
                },
                _ => ()
            }
        }

        Ok(())        
    }
}

struct MemoryAnalyzer {
    milestone_func_id: u32,
    milestones: Vec<u64>,
    threads: HashMap<u32, Vec<u32>>,
    stacklist: Vec<u32>,
    alloc_event: Vec<AllocEvent>,
}

#[derive(Debug)]
struct AllocEvent {
    kind: layout::Kind,
    tid: u32,
    time: u64,
    ptr: u64,
    size: u64,
    stackrange: Range<usize>,
}

#[derive(Default)]
struct StageResult {
    list: Vec<Vec<usize>>
}

struct AnalyzeResult {
    list: Vec<Vec<u64>>,
    leakmap: IndexMap<u64, usize>,
    selectmap: Vec<(usize, Vec<usize>)>,
}

struct SymbolTable<'a> {
    section_offset: u64,
    entry_map: layout::XRayInstrMap<'a>,
    symbol_map: object::read::SymbolMap<object::read::SymbolMapName<'a>>
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
            | layout::Kind::REALLOC_ALLOC
            | layout::Kind::REALLOC_DEALLOC => {
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
                    layout::Kind::ALLOC | layout::Kind::REALLOC_ALLOC => self.alloc_event.push(AllocEvent {
                        kind: event.kind,
                        tid: event.tid,
                        time: event.time,
                        ptr: alloc_event.ptr,
                        size: alloc_event.size,
                        stackrange
                    }),
                    layout::Kind::DEALLOC |layout::Kind::REALLOC_DEALLOC => self.alloc_event.push(AllocEvent {
                        kind: event.kind,
                        tid: event.tid,
                        time: event.time,
                        ptr: alloc_event.ptr,
                        size: alloc_event.size,
                        stackrange
                    }),
                    _ => unreachable!()
                }
            },
            _ => unreachable!()
        }

        Ok(())
    }

    fn split_and_cut(&mut self) -> StageResult {
        use rayon::prelude::*;
        
        self.threads = HashMap::new();

        self.milestones.sort_by_key(|&t| std::cmp::Reverse(t));
        self.alloc_event.par_sort_by_key(|ev| ev.time);

        let mut milestones = Vec::new();
        let mut next = self.alloc_event.as_slice();
        let mut prev = 0;

        while !next.is_empty() {
            if let Some(point) = self.milestones.pop() {
                let mid = next.partition_point(|ev| ev.time <= point);
                let (x, y) = next.split_at(mid);
                milestones.push(prev..(prev + x.len()));
                prev += x.len();
                next = y;
            } else {
                milestones.push(prev..(prev + next.len()));
                next = &[];
            }
        }

        let last_stage = milestones.len().saturating_sub(1);
        let mut list = milestones
            .into_iter()
            .enumerate()
            .par_bridge()
            .map(|(stage, range)| {
                let mut ptrmap: IndexMap<u64, _> = IndexMap::new();
                let mut keep = Vec::new();

                for idx in range {
                    let ev = &self.alloc_event[idx];

                    match ev.kind {
                        layout::Kind::ALLOC | layout::Kind::REALLOC_ALLOC => {
                            if let Some(oldidx) = ptrmap.insert(ev.ptr, idx)
                                .filter(|_| stage != last_stage)
                            {
                                println!(
                                    "[split/{}] bad alloc: ({}, {}) {:p}",
                                    stage, oldidx, idx, ev.ptr as *const u8
                                );
                            }
                        },
                        layout::Kind::DEALLOC | layout::Kind::REALLOC_DEALLOC => {
                            if let Some(oldidx) = ptrmap.swap_remove(&ev.ptr) {
                                let oldev = &self.alloc_event[oldidx];

                                if oldev.size != ev.size {
                                    keep.push(oldidx);
                                    keep.push(idx);
                                }
                            } else {
                                keep.push(idx);
                            }
                        },
                        _ => unreachable!()
                    }
                }

                keep.extend(ptrmap.into_values());
                keep.sort();
                keep
            })
            .collect::<Vec<_>>();
        list.sort_by_key(|list| list.first().copied());

        StageResult { list }
    }

    fn analyze(&self, subcmd: &SubCommand, result: &StageResult) -> anyhow::Result<AnalyzeResult> {
        let mut ptrmap = IndexMap::new();
        let mut heaplist: Vec<Vec<u64>> = Vec::with_capacity(result.list.len());
        let mut heap_count = 0;
        let mut selectmap = Vec::new();

        let selectlist = if let Some(selectstr) = subcmd.select.as_ref() {
            let mut list = Vec::new();
            for n in selectstr.split(',') {
                let n = n.parse()?;
                list.push(n)
            }
            list
        } else {
            Vec::new()
        };

        for (stage_idx, stage) in result.list.iter().enumerate() {
            let mut current = Vec::with_capacity(stage.len());
            
            for &idx in stage {
                let ev = &self.alloc_event[idx];

                match ev.kind {
                    layout::Kind::ALLOC | layout::Kind::REALLOC_ALLOC => {
                        if let Some(oldidx) = ptrmap.insert(ev.ptr, idx) {
                            println!(
                                "[analyze/{}] bad alloc: ({}, {}) {:p}",
                                stage_idx, oldidx, idx, ev.ptr as *const u8
                            );
                        }

                        heap_count += ev.size;
                    },
                    layout::Kind::DEALLOC | layout::Kind::REALLOC_DEALLOC => {
                        if ptrmap.swap_remove(&ev.ptr).is_none() {
                            println!(
                                "[analyze/{}] bad free: {} {:p}",
                                stage_idx, idx, ev.ptr as *const u8
                            );
                        };

                        heap_count -= ev.size;
                    },
                    _ => unreachable!()
                }

                current.push(heap_count);
            }

            if selectlist.contains(&stage_idx) {
                selectmap.push((stage_idx, ptrmap.values().copied().collect()));
            }

            heaplist.push(current);
        }

        Ok(AnalyzeResult {
            list: heaplist,
            leakmap: ptrmap,
            selectmap,
        })
    }

    fn track(&self, event_id: usize) -> Vec<usize> {
        use rayon::prelude::*;

        let ptr = self.alloc_event[event_id].ptr;
        
        let mut list = (0..self.alloc_event.len())
            .step_by(1024)
            .par_bridge()
            .map(|start| {
                (start..)
                    .take(1024)
                    .take_while(|&id| id < self.alloc_event.len())
                    .filter(|&id| self.alloc_event[id].ptr == ptr)
                    .collect::<Vec<_>>()
            })
            .reduce(Vec::new, |mut sum, mut next| {
                sum.append(&mut next);
                sum
            });
        list.sort();
        list
    }

    fn print_event(&self, symtab: &SymbolTable<'_>, event_id: usize, no_stack: bool)
        -> anyhow::Result<()>
    {
        let ev = self.alloc_event
            .get(event_id)
            .context("not found event id")?;

        println!("kind: {}", kind_to_str(ev.kind));
        println!("tid: {}", ev.tid);
        println!("time: {} ({:?})", ev.time, Duration::from_nanos(ev.time as _));
        println!("ptr: {:p}", ev.ptr as *const u8);
        println!("size: {}", ev.size);

        if !no_stack {
            println!("stack:");

            for stack_id in ev.stackrange.clone() {
                let func_id = self.stacklist[stack_id];
                let entry = symtab.entry_map.get(symtab.section_offset, func_id);
                let addr = entry.function();
                let symname = symtab.symbol_map.get(addr)
                    .map(|sym| sym.name())
                    .unwrap_or("unknown");
                let symname = addr2line::demangle_auto(symname.into(), None);
                println!("{:p} {}", addr as *const u8, symname);
            }
        }
        
        Ok(())        
    }

    fn write_flamegraph(
        &self,
        symtab: &SymbolTable,
        stage_result: &StageResult,
        analyze_result: &AnalyzeResult,
        path: &Path
    ) -> anyhow::Result<()> {
        use std::fmt::Write as _;

        let push_stack = |line: &mut String, ev: &AllocEvent| {
            for stackid in ev.stackrange.clone() {
                let func_id = self.stacklist[stackid];
                let entry = symtab.entry_map.get(symtab.section_offset, func_id);
                let name = symtab.symbol_map.get(entry.function())
                    .map(|sym| sym.name())
                    .unwrap_or("unknown");
                let name = addr2line::demangle_auto(name.into(), None);

                if !line.is_empty() {
                    line.push(';');
                }

                line.push_str(&name);
            }            
        };

        if !analyze_result.selectmap.is_empty() {
            let mut line = String::new();
            
            for (stage_idx, list) in &analyze_result.selectmap {
                let path = if analyze_result.selectmap.len() == 1 {
                    format!("{}", path.display())
                } else {
                    format!("{}.{}", path.display(), stage_idx)
                };
                let mut writer = fs::File::create(path)?;
                
                for &idx in list {
                    let ev = &self.alloc_event[idx];
                    push_stack(&mut line, ev);
                    writeln!(line, " {}", ev.size)?;
                    writer.write_all(line.as_bytes())?;
                    line.clear();
                }
            }
        } else {
            let mut writer = fs::File::create(path)?;
            let mut line = String::new();
            
            for &idx in analyze_result.leakmap.values() {
                if Some(idx) < stage_result.list.first().and_then(|list| list.last()).copied()
                    || Some(idx) > stage_result.list.last().and_then(|list| list.first()).copied()
                {
                    continue
                }
            
                let ev = &self.alloc_event[idx];
                push_stack(&mut line, ev);
                writeln!(line, " {}", ev.size)?;
                writer.write_all(line.as_bytes())?;
                line.clear();
            }
        }

        Ok(())
    }

    fn write_plot(
        &self,
        fold: bool,
        stage_result: &StageResult,
        analyze_result: &AnalyzeResult,
        path: &Path
    )
        -> anyhow::Result<()>
    {
        use plotly::{ Plot, Scatter };

        let mut plot = Plot::new();

        for (stage_idx, list) in analyze_result.list.iter().enumerate() {
            if fold {
                let x = (0..list.len()).collect();
                let y = list.clone();
                let t = stage_result.list[stage_idx]
                    .iter()
                    .map(|x| format!("e{}", x))
                    .collect();
                let trace = Scatter::new(x, y).text_array(t);
                plot.add_trace(trace);
            } else {
                let x = stage_result.list[stage_idx]
                    .iter()
                    .map(|x| format!("e{}", x))
                    .collect();
                let y = list.clone();
                let trace = Scatter::new(x, y).text_template("e%{x}");
                plot.add_trace(trace);
            }
            
        }

        plot.write_html(path);
        Ok(())
    }
}

fn kind_to_str(kind: layout::Kind) -> &'static str {
    match kind {
        layout::Kind::ALLOC => "alloc",
        layout::Kind::DEALLOC => "free",
        layout::Kind::REALLOC_ALLOC => "r/alloc",
        layout::Kind::REALLOC_DEALLOC => "r/free",
        _ => unreachable!()
    }
}
