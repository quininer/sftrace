use std::env;
use std::ffi::OsString;
use std::path::{ Path, PathBuf };
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
    cmd: Vec<OsString>,

    /// try print solib path and exit
    #[argh(switch)]
    print_solib: bool
}

fn sftracelib() -> String {
    format!("{}sftrace{}", std::env::consts::DLL_PREFIX, std::env::consts::DLL_SUFFIX)
}

fn search_sftracelib(datadir: &Path) -> anyhow::Result<PathBuf> {
    let name = sftracelib();

    let path = datadir.join(&name);
    if path.is_file() {
        return Ok(path);
    }
    
    let exd = env::current_exe()?;
    let exd = exd
        .parent()
        .context("current exe should have a parent dir")?;
    let path = exd.join(&name);
    if path.is_file() {
        return Ok(path);
    }

    anyhow::bail!("not found `{}`", name)
}

impl SubCommand {
    pub fn exec(self) -> anyhow::Result<()> {
        use std::os::unix::process::CommandExt;

        #[cfg(target_os = "linux")]
        const LIBRARY_PATH_NAME: &str = "LD_LIBRARY_PATH";

        #[cfg(target_os = "macos")]
        const LIBRARY_PATH_NAME: &str = "DYLD_LIBRARY_PATH";

        let cwd = env::current_dir()?;
        let projdir = directories::ProjectDirs::from("", "", "sftrace")
            .context("not found project dir")?;        

        if self.print_solib {
            let path = search_sftracelib(projdir.data_dir())?;
            print!("{}", path.display());
            return Ok(())
        }
        
        let mut iter = self.cmd.iter();
        let exe = iter.next().context("need command")?;

        let output = self.output.clone()
            .unwrap_or_else(|| cwd.join("sf.log"));

        let mut cmd = Command::new(exe);
        cmd
            .args(iter)
            .env("SFTRACE_OUTPUT_FILE", output);

        if let Some(path) = self.filter.as_ref() {
            cmd.env("SFTRACE_FILTER", path);
        }

        if env::var_os(LIBRARY_PATH_NAME).is_none() {
            let solib = match self.solib.as_ref() {
                Some(p) => p.clone(),
                None => search_sftracelib(&projdir.data_dir())?
            };

            let libdir = solib.parent().unwrap();
            cmd.env(LIBRARY_PATH_NAME, libdir);
        }

        Err(cmd.exec())?
    }
}
