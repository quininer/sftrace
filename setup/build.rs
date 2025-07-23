use std::path::PathBuf;

fn main() {
    let name = "SFTRACE_DYLIB_DIR";

    println!("cargo::rerun-if-env-changed={}", name);

    let path = match std::env::var(name).ok() {
        Some(path) => Some(PathBuf::from(path)),
        None => search_sftracelib_dir(),
    };

    if let Some(dir) = path {
        let link = std::env::var("CARGO_MANIFEST_LINKS").unwrap();

        println!("cargo::rustc-link-search=native={}", dir.display());
        println!("cargo::rustc-link-lib=dylib={}", link);
    }
}

fn search_sftracelib_dir() -> Option<PathBuf> {
    use std::process::{Command, Stdio};

    let result = Command::new("sftrace")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .arg("record")
        .arg("--print-solib")
        .output();

    match result {
        Ok(output) if output.status.success() => {
            let out = String::from_utf8(output.stdout).ok()?;
            let mut out = PathBuf::from(out);
            out.pop();
            Some(out)
        }
        _ => None,
    }
}
