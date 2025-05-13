#[path = "../layout.rs"]
mod layout;
mod util;

mod config;
mod convert;
mod filter;

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
    Filter(filter::SubCommand)
}

fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    match options.subcmd {
        SubCommand::Convert(cmd) => cmd.exec(),
        SubCommand::Filter(cmd) => cmd.exec()
    }
}

