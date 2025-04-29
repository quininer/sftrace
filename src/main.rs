mod layout;

use std::fs;
use std::path::PathBuf;
use anyhow::Context;
use argh::FromArgs;
use zerocopy::FromBytes;

/// sftrace tools
#[derive(FromArgs)]
struct Options {
    /// sftrace trace file path
    #[argh(positional)]
    path: PathBuf
}

fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    let fd = fs::File::open(&options.path)?;
    let mmap = unsafe {
        memmap2::Mmap::map(&fd)?
    };

    let log = layout::LogFile::ref_from_bytes(mmap.as_ref())
        .ok()
        .context("log parse failed")?;
    if log.metadata.sign != *layout::SIGN {
        anyhow::bail!("not is sftrace log: {:?}", log.metadata.sign);
    }
    
    todo!()
}
