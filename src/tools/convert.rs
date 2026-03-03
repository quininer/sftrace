mod chrome_trace;

use crate::layout;
use anyhow::Context;
use argh::FromArgs;
use object::{Object, ObjectSection};
use std::cell::RefCell;
use std::collections::{HashMap, hash_map};
use std::io::Read;
use std::path::PathBuf;
use std::{fs, io};
use zerocopy::FromBytes;

/// Convert command
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "convert")]
pub struct SubCommand {
    /// sftrace trace path
    #[argh(positional)]
    path: PathBuf,

    /// debug symbol path
    #[argh(option, short = 's')]
    symbol: Option<PathBuf>,

    /// filter config
    #[argh(option, short = 'c')]
    config: Option<PathBuf>,

    /// output type
    #[argh(option)]
    r#type: Type,

    /// chrome-trace output path
    #[argh(option, short = 'o')]
    output: PathBuf,
}

#[derive(argh::FromArgValue)]
#[derive(PartialEq, Eq, Debug)]
enum Type {
    ChromeTrace,
    Pola,
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
        let pid = metadata.pid.try_into().context("bad pid")?;

        let sympath = self.symbol.as_ref().unwrap_or(&metadata.shlib_path);
        let symfd = fs::File::open(sympath)?;
        let symbuf = unsafe { memmap2::Mmap::map(&symfd)? };
        let symobj = object::File::parse(&*symbuf)?;
        let xray_section = symobj
            .section_by_name("xray_instr_map")
            .context("not found xray_instr_map section")?;
        let xray_buf = xray_section.uncompressed_data()?;

        let entry_map = <[layout::XRayFunctionEntry]>::ref_from_bytes(xray_buf.as_ref())
            .map_err(|err| anyhow::format_err!("xray_instr_map parse failed: {:?}", err))?;
        let entry_map = layout::XRayInstrMap(entry_map);

        if let Ok(Some(build_id)) = symobj.build_id()
            && metadata.shlibid != build_id
        {
            anyhow::bail!(
                "build id does not match: {:?} vs {:?}",
                metadata.shlibid,
                build_id
            );
        }

        let loader = addr2line::Loader::new(sympath)
            .map_err(|err| anyhow::format_err!("parse symbol failed: {:?}", err))?;
        let loader = Addr2Line::new(loader);

        let mut state = State {
            metadata: &metadata,
            loader: &loader,
            process_id: pid,
            section_offset: xray_section.address(),
            entry_map,
            stack: HashMap::new(),
        };
        let mut writer = chrome_trace::PacketWriter::default();

        writer.convert(&mut log, &mut state, &self.output)?;

        Ok(())
    }
}

struct State<'g> {
    #[allow(dead_code)]
    metadata: &'g layout::Metadata,
    loader: &'g Addr2Line,
    process_id: i32,
    section_offset: u64,
    entry_map: layout::XRayInstrMap<'g>,
    stack: HashMap<u32, Vec<u32>>,
}

struct Addr2Line {
    loader: addr2line::Loader,
    cache: RefCell<HashMap<u64, Option<Frame>>>,
}

#[derive(Clone)]
struct Frame {
    name: String,
    file: Option<String>,
    line: Option<u32>,
}

impl Addr2Line {
    fn new(loader: addr2line::Loader) -> Self {
        Addr2Line {
            loader,
            cache: RefCell::new(HashMap::new()),
        }
    }

    fn lookup(&self, addr: u64) -> Option<Frame> {
        let mut cache = self.cache.borrow_mut();

        match cache.entry(addr) {
            hash_map::Entry::Occupied(entry) => entry.get().clone(),
            hash_map::Entry::Vacant(entry) => {
                let frame = self
                    .loader
                    .find_frames(addr)
                    .ok()
                    .and_then(|mut iter| iter.next().ok())
                    .flatten()
                    .map(|frame| Frame {
                        name: frame
                            .function
                            .and_then(|name| name.demangle().map(|name| name.into_owned()).ok())
                            .or_else(|| {
                                self.loader
                                    .find_symbol(addr)
                                    .map(|name| name.to_owned())
                                    .map(|name| {
                                        addr2line::demangle_auto(name.into(), None).into_owned()
                                    })
                            })
                            .unwrap_or_else(|| "unknown".into()),
                        file: frame
                            .location
                            .as_ref()
                            .and_then(|loc| loc.file)
                            .map(|file| file.to_owned()),
                        line: frame.location.as_ref().and_then(|loc| loc.line),
                    })
                    .or_else(|| {
                        Some(Frame {
                            name: self
                                .loader
                                .find_symbol(addr)
                                .map(|name| name.to_owned())
                                .map(|name| {
                                    addr2line::demangle_auto(name.into(), None).into_owned()
                                })?,
                            file: None,
                            line: None,
                        })
                    });
                entry.insert(frame).clone()
            }
        }
    }
}
