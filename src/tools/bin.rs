#![allow(clippy::uninlined_format_args)]

#[path = "../layout.rs"]
mod layout;
mod util;

mod convert;
mod filter;
mod memory;
mod record;

use argh::FromArgs;

/// sftrace tools
#[derive(FromArgs)]
struct Options {
    #[argh(subcommand)]
    subcmd: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Convert(convert::SubCommand),
    Filter(filter::SubCommand),
    Memory(memory::SubCommand),
    Record(record::SubCommand),
}

fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    match options.subcmd {
        SubCommand::Convert(cmd) => cmd.exec(),
        SubCommand::Filter(cmd) => cmd.exec(),
        SubCommand::Memory(cmd) => cmd.exec(),
        SubCommand::Record(cmd) => cmd.exec(),
    }
}

