use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use argh::FromArgs;
use anyhow::Context;


/// Record command
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "record")]
pub struct SubCommand {
    /// the `libsftrace.so` path
    #[argh(option)]
    solib: Option<PathBuf>,

    /// filter file
    #[argh(option, short = 'f')]
    filter: Option<PathBuf>,

    /// output log file
    #[argh(option, short = 'o')]
    output: Option<PathBuf>,

    /// command
    #[argh(positional, greedy)]
    cmd: Vec<OsString>
}

fn sftracelib() -> String {
    format!("{}sftrace{}", std::env::consts::DLL_PREFIX, std::env::consts::DLL_SUFFIX)
}

impl SubCommand {
    pub fn exec(self) -> anyhow::Result<()> {
        use std::os::unix::process::CommandExt;

        #[cfg(target_os = "linux")]
        const LIBRARY_PATH_NAME: &str = "LD_LIBRARY_PATH";
        
        let mut iter = self.cmd.iter();
        let exe = iter.next().context("need command")?;

        let cwd = env::current_dir()?;
        let exd = env::current_exe()?
            .parent()
            .context("current exe should have a parent dir")?
            .to_owned();
        let projdir = directories::ProjectDirs::from("", "", "sftrace")
            .context("not found project dir")?;

        let output = self.output.clone()
            .unwrap_or_else(|| cwd.join("sf.log"));

        let mut cmd = Command::new(exe);
        cmd
            .args(iter)
            .env("SFTRACE_OUTPUT_FILE", output);

        if let Some(path) = self.filter.as_ref() {
            cmd.env("SFTRACE_FILTER", path);
        }

        if env::var_os("LIBRARY_PATH_NAME").is_none() {
            let solib = self.solib.clone()
                .or_else(|| Some(projdir.data_dir().join(sftracelib())))
                .filter(|path| path.is_file())
                .or_else(|| Some(exd.join(sftracelib())))
                .filter(|path| path.is_file())
                .with_context(|| format!("not found `{}`", sftracelib()))?;

            let libdir = solib.parent().unwrap();
            cmd.env("LIBRARY_PATH_NAME", libdir);
        }

        Err(cmd.exec())?
    }
}
