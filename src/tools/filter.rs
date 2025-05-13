use std::fs;
use std::io::Write;
use std::ffi::OsStr;
use std::path::PathBuf;
use argh::FromArgs;
use anyhow::Context;
use object::{ Object, ObjectSymbol };
use rayon::prelude::*;
use zerocopy::IntoBytes;
use crate::{ layout, config };


/// Filter command
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "filter")]
pub struct SubCommand {
    /// object file path
    #[argh(option, short = 'p')]
    path: Option<PathBuf>,

    /// filter by rlib
    #[argh(option, short = 'r')]
    rlibs: Option<String>,

    /// filter config
    #[argh(option, short = 'c')]
    config: Option<PathBuf>,

    /// filter-file output path
    #[argh(option, short = 'o')]
    output: PathBuf,    
}

impl SubCommand {
    pub fn exec(&self) -> anyhow::Result<()> {
        let config = if let Some(path) = self.config.as_ref() {
            let buf = fs::read_to_string(path)?;
            let mut config: config::Config = toml::from_str(&buf)?;
            config.make();
            config
        } else {
            Default::default()
        };

        let objpath = config.path()
            .or(self.path.as_deref())
            .context("need object path")?;
        let objfd = fs::File::open(objpath)?;
        let objbuf = unsafe { memmap2::Mmap::map(&objfd)? };
        let obj = object::File::parse(&*objbuf)?;

        if let Some(rlibs) = config.rlibs().or(self.rlibs.as_deref()) {
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
                        })
                        .map(|sym| {
                            let name = sym.name_bytes().unwrap();
                            let hint = config.record_args().binary_search_by_key(&name, |s| s.as_bytes()).is_ok();
                            layout::FilterMark::new(sym.address(), hint).expect("big address")
                        })
                        .collect::<Vec<_>>()
                })
                .reduce(Vec::new, |mut sum, mut next| {
                    sum.append(&mut next);
                    sum
                });
            map.par_sort();
            map.dedup();

            println!("done {:?}", map.len());

            let mut output = fs::File::create(&self.output)?;
            let hash = obj.build_id()
                .ok()
                .flatten()
                .map(layout::build_id_hash)
                .unwrap_or_default();
            output.write_all(layout::SIGN_FILTE)?;
            output.write_all(&hash.to_ne_bytes())?;
            output.write_all(layout::FilterMode::FILTER.as_bytes())?;
            output.write_all(map.as_bytes())?;
        } else {
            let map = obj.symbols()
                .filter(|sym| matches!(sym.kind(), object::SymbolKind::Text))
                .filter(|sym| sym.is_definition())
                .filter(|sym| sym.name_bytes()
                    .ok()
                    .filter(|name| config
                        .record_args()
                        .binary_search_by_key(name, |s| s.as_bytes())
                        .is_ok()
                    )
                    .is_some()
                )
                .map(|sym| layout::FilterMark::new(sym.address(), true).expect("big address"))
                .collect::<Vec<_>>();

            println!("done {:?}", map.len());

            let mut output = fs::File::create(&self.output)?;
            let hash = obj.build_id()
                .ok()
                .flatten()
                .map(layout::build_id_hash)
                .unwrap_or_default();
            output.write_all(layout::SIGN_FILTE)?;
            output.write_all(&hash.to_ne_bytes())?;
            output.write_all(layout::FilterMode::MARK.as_bytes())?;
            output.write_all(map.as_bytes())?;            
        }

        Ok(())   
    }
}
