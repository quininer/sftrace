mod util;
mod layout;
mod events;
mod arch;

use std::fs;
use std::io::Write;
use std::sync::OnceLock;
use object::{ Object, ObjectSection };
use util::{ MProtect, page_size };


#[unsafe(no_mangle)]
pub extern "C" fn sftrace_setup(
    entry_slot: unsafe extern "C" fn(),
    exit_slot: unsafe extern "C" fn(),
    tailcall_slot: unsafe extern "C" fn(),
) {
    use std::sync::Once;

    static ONCE: Once = Once::new();

    ONCE.call_once(|| init(
        entry_slot,
        exit_slot,
        tailcall_slot
    ));
}

#[unsafe(no_mangle)]
pub extern "C" fn sftrace_alloc_event(
    kind: u8,
    size: usize,
    align: usize,
    ptr: *mut u8    
) {
    events::record_alloc(kind, size, align, ptr);
}

static OUTPUT: OnceLock<fs::File> = OnceLock::new();

fn init(
    entry_slot: unsafe extern "C" fn(),
    exit_slot: unsafe extern "C" fn(),
    tailcall_slot: unsafe extern "C" fn(),
) { 
    patch_xray(
        entry_slot,
        exit_slot,
        tailcall_slot
    );
    
    unsafe {
        match libc::atexit(shutdown) {
            0 => (),
            err => panic!("atexit failed: {:?}", err)
        }
    }
}

fn patch_xray(
    entry_slot: unsafe extern "C" fn(),
    exit_slot: unsafe extern "C" fn(),
    tailcall_slot: unsafe extern "C" fn(),
) {
    use zerocopy::FromBytes;
    use findshlibs::{ SharedLibrary, Segment };

    let Some(outfile) = std::env::var_os("SFTRACE_OUTPUT_FILE")
        else { return };

    let page_size = page_size();

    findshlibs::TargetSharedLibrary::each(|shlib| {
        let base = shlib.actual_load_addr();
        let shlibid = match shlib.id() {
            Some(id) => id.as_bytes().to_owned(),
            None => return,
        };

        if !(base.0..base.0 + shlib.len()).contains(&(entry_slot as usize)) {
            return;
        }
        
        let Ok(fd) = std::fs::File::open(shlib.name())
            else { return };
        let Ok(buf) = (unsafe { memmap2::Mmap::map(&fd) })
            else { return };
        let Ok(obj) = object::File::parse(buf.as_ref())
            else { return };
        let Some(xray_section) = obj.section_by_name("xray_instr_map")
            else { return };
        let Ok(buf) = xray_section.uncompressed_data()
            else { return };

        if let Ok(Some(build_id)) = obj.build_id() {
            if shlibid != build_id {
                eprintln!("build id does not match: {:?} vs {:?}", shlibid, build_id);
                return;
            }
        }

        let mut maybe_filter_buf = None;
        if let Ok(path) = std::env::var("SFTRACE_FILTER") {
            let fd = fs::File::open(&path).unwrap();
            let buf = unsafe { memmap2::Mmap::map(&fd).unwrap() };
            maybe_filter_buf = Some(buf);
        }
        let maybe_filter = if let Some(buf) = maybe_filter_buf.as_ref() {
            Some(layout::FilterMap::parse(&buf, obj.build_id().ok().flatten()).unwrap())
        } else {
            None
        };

        let Some((text_addr, text_len)) = shlib.segments()
            .filter(|seg| seg.is_code() && seg.len() != 0)
            .map(|seg| (seg.actual_virtual_memory_address(shlib), seg.len()))
            .filter(|(addr, len)| (addr.0..addr.0 + len).contains(&(entry_slot as usize)))
            .next()
            .map(|(text_addr, text_len)| {
                let addr = text_addr.0 & !(page_size - 1);
                let len = text_addr.0 + text_len - addr;
                let len = (len + page_size - 1) & !(page_size - 1);
                (addr, len)
            })
            else { return };

        {
            let mut fd = fs::OpenOptions::new()
                .create_new(true)
                .append(true)
                .open(&outfile)
                .expect("open output file failed");
            let metadata = layout::Metadata {
                shlibid,
                pid: std::process::id(),
                shlib_base: base.0 as u64,
                shlib_path: shlib.name().into()
            };
            fd.write_all(layout::SIGN_TRACE).unwrap();
            cbor4ii::serde::to_writer(&mut fd, &metadata).unwrap();
            OUTPUT.set(fd).ok().expect("already initialized");
        }

        let _guard = unsafe {
            MProtect::unlock(text_addr as *mut u8, text_len)
        };

        let entry_map = <[layout::XRayFunctionEntry]>::ref_from_bytes(buf.as_ref()).unwrap();
        let (entry_slot, exit_slot, tailcall_slot) = if cfg!(target_arch = "aarch64") {
            (
                arch::xray_entry as _,
                arch::xray_exit as _,
                arch::xray_tailcall as _
            )
        } else {
            (entry_slot, exit_slot, tailcall_slot)
        };

        for entry in layout::XRayInstrMap(entry_map).iter(xray_section.address()) {
            let mut flag = layout::FuncFlag::empty();
            
            if let Some(filter) = maybe_filter {
                match (filter.mode(), filter.check(entry.function())) {
                    (layout::FilterMode::MARK, Some(mark)) => flag |= mark.flag(),
                    (layout::FilterMode::MARK, _) => (),
                    (layout::FilterMode::FILTER, Some(mark)) => flag |= mark.flag(),
                    (layout::FilterMode::FILTER, None) => continue,
                    (..) => continue
                }
            }

            let func_id = FuncId::pack(entry.id(), flag).unwrap();
            let func_id = func_id.0;

            let base = if cfg!(target_os = "macos") {
                match obj.kind() {
                    object::ObjectKind::Executable => 0,
                    object::ObjectKind::Dynamic => base.0,
                    kind => {
                        eprintln!("unsupported object kind: {:?}", kind);
                        base.0
                    }
                }
            } else {
                base.0
            };
            let addr: usize = entry.address().try_into().unwrap();
            let addr = base + addr;

            // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/include/llvm/CodeGen/AsmPrinter.h#L338
            unsafe {
                match entry.kind() {
                    // entry
                    0 => arch::patch_entry(addr, func_id, entry_slot),
                    // exit
                    1 => arch::patch_exit(addr, func_id, exit_slot),
                    // tail call
                    2 => arch::patch_tailcall(addr, func_id, tailcall_slot),
                    kind => eprintln!("unsupport kind: {}", kind)
                }
            }
        }

        #[cfg(not(target_arch = "aarch64"))]
        unsafe {
            arch::patch_slot(entry_slot as *mut u8, arch::xray_entry as usize);
            arch::patch_slot(exit_slot as *mut u8, arch::xray_exit as usize);
            arch::patch_slot(tailcall_slot as *mut u8, arch::xray_tailcall as usize);
        }
    });    
}

extern "C" fn shutdown() {
    // TODO flush all thread ?
    events::flush_current_thread();
}

#[derive(Clone, Copy)]
struct FuncId(u32);

impl FuncId {
    const CAP: usize = 32 - 8;
    
    fn pack(idx: u32, flag: layout::FuncFlag) -> Option<FuncId> {
        let func_id = idx + 1;
        let flag = (flag.bits() as u32) << Self::CAP;

        (func_id < (1 << Self::CAP)).then(|| FuncId(flag | func_id))
    }

    fn unpack(self) -> (u32, layout::FuncFlag) {
        let func_id = self.0 & ((1 << Self::CAP) - 1);
        let flag = layout::FuncFlag::from_bits_truncate((self.0 >> Self::CAP) as u8);

        (func_id - 1, flag)
    }
}
