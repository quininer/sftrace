mod util;
mod layout;
mod events;
mod arch;

use std::io::Write;
use std::{ ptr, fs };
use std::sync::OnceLock;
use object::{ Object, ObjectSection };
use util::{ ScopeGuard, page_size };


#[no_mangle]
pub extern "C" fn sftrace_setup(
    entry_slot: unsafe extern "C" fn(),
    exit_slot: unsafe extern "C" fn()    
) {
    use std::sync::Once;

    static ONCE: Once = Once::new();

    ONCE.call_once(|| init(entry_slot, exit_slot));
}

static OUTPUT: OnceLock<fs::File> = OnceLock::new();

fn init(
    entry_slot: unsafe extern "C" fn(),
    exit_slot: unsafe extern "C" fn()    
) {
    patch_xray(entry_slot, exit_slot);
    
    unsafe {
        match libc::atexit(shutdown) {
            0 => (),
            err => panic!("atexit failed: {:?}", err)
        }
    }
}

fn patch_xray(
    entry_slot: unsafe extern "C" fn(),
    exit_slot: unsafe extern "C" fn()    
) {
    use zerocopy::{ IntoBytes, FromBytes, Immutable, KnownLayout };
    use findshlibs::{ SharedLibrary, Segment };

    // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/lib/CodeGen/AsmPrinter/AsmPrinter.cpp#L4447
    #[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
    #[repr(C)]
    struct XRayFunctionEntry {
        address: usize,
        function: usize,
        kind: u8,
        always_instrument: u8,
        version: u8,
        padding: [u8; (4 * 8) - ((2 * 8) + 3)]
    }

    const _ASSERT_ARCH: () = if !cfg!(target_pointer_width = "64") {
        panic!("64bit only")
    };
    const _ASSERT_SIZE: () = [(); 1][std::mem::size_of::<XRayFunctionEntry>() - 32];

    let page_size = page_size();

    findshlibs::TargetSharedLibrary::each(|shlib| {
        let base = shlib.actual_load_addr();

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

        let Some((text_addr, text_len)) = shlib.segments()
            .filter(|seg| seg.is_code() && seg.len() != 0)
            .map(|seg| (seg.actual_virtual_memory_address(shlib), seg.len()))
            .filter(|(addr, len)| (addr.0..addr.0 + len).contains(&(entry_slot as usize)))
            .next()
            .map(|(text_addr, text_len)| {
                let addr = text_addr.0 & !(page_size - 1);
                let len = text_addr.0 + text_len - addr;
                (addr, len)
            })
            else { return };

        {
            let path = std::env::var_os("SFTRACE_OUTPUT_FILE").expect("need SFTRACE_OUTPUT_FILE");
            let mut fd = fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .expect("open output file failed");
            let metadata = layout::Metadata {
                sign: *layout::SIGN,
                base: (base.0 as u64).into()
            };
            fd.write_all(metadata.as_bytes()).unwrap();
            OUTPUT.set(fd).ok().expect("already initialized");
        }

        // unlock
        unsafe {
            if libc::mprotect(
                text_addr as *mut _,
                text_len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
            ) != 0 {
                panic!("text segment unlock failed: {:?}", std::io::Error::last_os_error());
            }
        }

        // lock it back
        let _guard = ScopeGuard((), |_| unsafe {
            if libc::mprotect(
                text_addr as *mut _,
                text_len,
                libc::PROT_READ | libc::PROT_EXEC
            ) != 0 {
                panic!("text segment lock failed: {:?}", std::io::Error::last_os_error());
            }
        });

        let (entry_map, tail) = <[XRayFunctionEntry]>::ref_from_prefix_with_elems(
            buf.as_ref(),
            buf.len() / std::mem::size_of::<XRayFunctionEntry>()
        ).unwrap();
        assert!(tail.is_empty());

        for (i, entry) in entry_map.iter()
            .enumerate()
            .filter(|(_, entry)| entry.version == 2)
        {
            let section_offset: usize = xray_section.address().try_into().unwrap();
            let entry_offset = section_offset + i * std::mem::size_of::<XRayFunctionEntry>();
            
            // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/compiler-rt/lib/xray/xray_interface_internal.h#L59
            // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/lib/XRay/InstrumentationMap.cpp#L199
            let address = base.0 + entry_offset + entry.address;
            let _function = base.0 + entry_offset + entry.address + std::mem::size_of::<usize>();

            // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/include/llvm/CodeGen/AsmPrinter.h#L338
            unsafe {
                match entry.kind {
                    // entry
                    0 => patch_entry(address, entry_slot),
                    // exit
                    1 => patch_exit(address, exit_slot),
                    _ => ()
                }
            }
        }

        unsafe {
            patch_slot(entry_slot as *mut u8, arch::xray_entry as usize);
            patch_slot(exit_slot as *mut u8, arch::xray_exit as usize);
        }        
    });    
}

unsafe fn patch_slot(slot: *mut u8, target: usize) {
    const TRAMPOLINE: [u8; 8] = [0x3e, 0xff, 0x25, 0x01, 0x00, 0x00, 0x00, 0xcc];

    // TODO support more arch
    assert!(cfg!(target_arch = "x86_64"));    

    slot.copy_from_nonoverlapping(TRAMPOLINE.as_ptr(), TRAMPOLINE.len());
    slot.byte_add(TRAMPOLINE.len()).cast::<u64>().write(target as u64);
}

// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/compiler-rt/lib/xray/xray_x86_64.cpp#L123
unsafe fn patch_entry(address: usize, slot: unsafe extern "C" fn()) {
    use std::sync::atomic::{ self, AtomicU16 };

    const CALL_OP_CODE: u8 = 0xe8;
    const MOV_R10_SEQ: u16 = 0xba41;

    // TODO support more arch
    assert!(cfg!(target_arch = "x86_64"));
    
    let trampoline = slot as usize;

    let offset = (trampoline as isize) - (address + 11) as isize;
    let offset = offset.try_into().unwrap();

    let addr = ptr::null_mut::<u8>().with_addr(address);

    unsafe {
        addr.byte_add(2).cast::<u32>().write(0);
        addr.byte_add(6).write(CALL_OP_CODE);
        addr.byte_add(7).cast::<i32>().write(offset);
        AtomicU16::from_ptr(addr.cast())
            .store(MOV_R10_SEQ, atomic::Ordering::Release);
    }
}

unsafe fn patch_exit(address: usize, slot: unsafe extern "C" fn()) {
    use std::sync::atomic::{ self, AtomicU16 };
    
    const JMP_OP_CODE: u8 = 0xe9;
    const MOV_R10_SEQ: u16 = 0xba41;

    // TODO support more arch
    assert!(cfg!(target_arch = "x86_64"));
    
    let trampoline = slot as usize;

    let offset = (trampoline as isize) - (address + 11) as isize;
    let offset = offset.try_into().unwrap();

    let addr = ptr::null_mut::<u8>().with_addr(address);

    unsafe {
        addr.byte_add(2).cast::<u32>().write(0);
        addr.byte_add(6).write(JMP_OP_CODE);
        addr.byte_add(7).cast::<i32>().write(offset);
        AtomicU16::from_ptr(addr.cast())
            .store(MOV_R10_SEQ, atomic::Ordering::Release);
    }
}

extern "C" fn shutdown() {
    events::flush_current_thread();
}
