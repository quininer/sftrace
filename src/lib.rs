mod util;
mod events;

use std::path::{ PathBuf, Path };
use std::arch::asm;
use events::GlobalEventList;


#[no_mangle]
pub unsafe extern "C" fn mcount() {
    let mut addr: *const u8;
    let mut sp: *const u8;

    asm!{
        "mov {addr}, [rbp + 8]",
        "mov {sp}, rsp",
        addr = out(reg) addr,
        sp = out(reg) sp
    }

    init();

    GlobalEventList.record(addr, sp);
}

fn init() {
    use std::sync::Once;

    static INIT: Once = Once::new();

    INIT.call_once(|| unsafe {
        match libc::atexit(dtor) {
            0 => (),
            err => panic!("atexit failed: {:?}", err)
        }
    });
}

extern "C" fn dtor() {
    use std::io::Write;

    std::fs::copy("/proc/self/maps", output().join("maps")).unwrap();

    let list = GlobalEventList.take();
    let mut fd = std::fs::File::create(output().join("logs")).unwrap();

    write!(&mut fd, "{:#?}", list).unwrap();
}

fn output() -> &'static Path {
    use std::sync::OnceLock;
    static OUTPUT: OnceLock<PathBuf> = OnceLock::new();

    OUTPUT.get_or_init(|| {
        std::env::var_os("SFTRACE_OUTPUT_DIR")
            .unwrap()
            .into()
    })
}
