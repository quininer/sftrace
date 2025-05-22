fn main() {
    let name = "SFTRACE_DYLIB_DIR";
    
    println!("cargo::rerun-if-env-changed={}", name);

    if let Ok(dir) = std::env::var(name) {
        let link = std::env::var("CARGO_MANIFEST_LINKS").unwrap();
        
        println!("cargo::rustc-link-search=native={}", dir);
        println!("cargo::rustc-link-lib=dylib={}", link);
    }
}
