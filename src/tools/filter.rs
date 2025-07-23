use crate::layout;
use argh::FromArgs;
use object::Object;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use zerocopy::IntoBytes;

/// Filter command
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "filter")]
pub struct SubCommand {
    /// object file path
    #[argh(option, short = 'p')]
    path: PathBuf,

    /// filter by list
    #[argh(option)]
    list: Option<PathBuf>,

    /// filter by regex
    #[argh(option, short = 'r')]
    regex: Option<String>,

    /// filter-file output path
    #[argh(option, short = 'o')]
    output: PathBuf,
}

impl SubCommand {
    pub fn exec(&self) -> anyhow::Result<()> {
        let objfd = fs::File::open(&self.path)?;
        let objbuf = unsafe { memmap2::Mmap::map(&objfd)? };
        let obj = object::File::parse(&*objbuf)?;

        let listbuf = if let Some(path) = self.list.as_ref() {
            fs::read_to_string(path)?
        } else {
            String::new()
        };
        let listmap = listbuf.lines().collect::<HashSet<_>>();

        let symmap = obj.symbol_map();
        let mut map = Vec::new();

        let maybe_regex = if let Some(s) = self.regex.as_ref() {
            Some(regex::Regex::new(s)?)
        } else {
            None
        };

        for sym in symmap.symbols() {
            let mut hint = false;

            if listmap.contains(sym.name())
                || maybe_regex
                    .as_ref()
                    .filter(|re| re.is_match(sym.name()))
                    .is_some()
            {
                hint = true;
            }

            if hint {
                let mark =
                    layout::FilterMark::new(sym.address(), layout::FuncFlag::empty()).unwrap();
                map.push(mark);
            }
        }

        map.sort_by_key(|mark| mark.addr());
        map.dedup();

        println!("done {:?}", map.len());

        let mut output = fs::File::create(&self.output)?;
        let hash = obj
            .build_id()
            .ok()
            .flatten()
            .map(layout::build_id_hash)
            .unwrap_or_default();
        output.write_all(layout::SIGN_FILTE)?;
        output.write_all(&hash.to_ne_bytes())?;
        output.write_all(layout::FilterMode::FILTER.as_bytes())?;
        output.write_all(map.as_bytes())?;

        Ok(())
    }
}
