mod util;
mod layout;
mod events;
mod arch;

use std::io::Write;
use std::{ ptr, fs };
use std::sync::OnceLock;
use std::sync::atomic::{ self, AtomicU16 };
use object::{ Object, ObjectSection };
use zerocopy::{ FromBytes, Immutable, KnownLayout };
use util::{ ScopeGuard, page_size };


#[no_mangle]
pub extern "C" fn sftrace_setup(
    entry_slot: unsafe extern "C" fn(),
    exit_slot: unsafe extern "C" fn(),
    tailcall_slot: unsafe extern "C" fn(),
) {
    use std::sync::Once;

    static ONCE: Once = Once::new();

    ONCE.call_once(|| init(entry_slot, exit_slot, tailcall_slot));
}

static OUTPUT: OnceLock<fs::File> = OnceLock::new();

fn init(
    entry_slot: unsafe extern "C" fn(),
    exit_slot: unsafe extern "C" fn(),
    tailcall_slot: unsafe extern "C" fn(),
) {
    patch_xray(entry_slot, exit_slot, tailcall_slot);
    
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
    use findshlibs::{ SharedLibrary, Segment };

    const _ASSERT_ARCH: () = if !cfg!(target_pointer_width = "64") {
        panic!("64bit only")
    };

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
                shlibid,
                pid: std::process::id(),
                shlib_base: base.0 as u64,
                shlib_path: shlib.name().into()
            };
            fd.write_all(layout::SIGN).unwrap();
            cbor4ii::serde::to_writer(&mut fd, &metadata).unwrap();
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

        let entry_map = <[XRayFunctionEntry]>::ref_from_bytes(buf.as_ref()).unwrap();
        let section_offset: usize = xray_section.address().try_into().unwrap();

        for (addr, _func, entry) in XRayInstrMap(entry_map)
            .iter(base.0, section_offset)
        {
            // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/include/llvm/CodeGen/AsmPrinter.h#L338
            unsafe {
                match entry.kind {
                    // entry
                    0 => patch_entry(addr, entry_slot),
                    // exit
                    1 => patch_exit(addr, exit_slot),
                    // tail call
                    2 => patch_tailcall(addr, tailcall_slot),
                    _ => eprintln!("unsupport kind: {}", entry.kind)
                }
            }
        }

        unsafe {
            patch_slot(entry_slot as *mut u8, arch::xray_entry as usize);
            patch_slot(exit_slot as *mut u8, arch::xray_exit as usize);
            patch_slot(tailcall_slot as *mut u8, arch::xray_tailcall as usize);
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

// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/compiler-rt/lib/xray/xray_x86_64.cpp#L224
unsafe fn patch_tailcall(address: usize, slot: unsafe extern "C" fn()) {
    patch_entry(address, slot);
}

extern "C" fn shutdown() {
    events::flush_current_thread();
}

// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/lib/CodeGen/AsmPrinter/AsmPrinter.cpp#L4447
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct XRayFunctionEntry {
    pub address: usize,
    pub function: usize,
    pub kind: u8,
    pub always_instrument: u8,
    pub version: u8,
    padding: [u8; (4 * 8) - ((2 * 8) + 3)]
}

const _ASSERT_SIZE: () = [(); 1][std::mem::size_of::<XRayFunctionEntry>() - 32];

pub struct XRayInstrMap<'a>(pub &'a [XRayFunctionEntry]);

impl XRayInstrMap<'_> {
    pub fn iter(&self, base: usize, section_offset: usize) -> impl Iterator<Item = (usize, usize, &'_ XRayFunctionEntry)> + '_ {
        const ENTRY_SIZE: usize = std::mem::size_of::<XRayFunctionEntry>();
        
        self.0.iter()
            .enumerate()
            .filter(|(_, entry)| entry.version == 2)
            .map(move |(i, entry)| {
                let entry_offset = section_offset + i * ENTRY_SIZE;

                // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/compiler-rt/lib/xray/xray_interface_internal.h#L59
                // https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/llvm/lib/XRay/InstrumentationMap.cpp#L199                
                let address = base + entry_offset + entry.address;
                let function = base + entry_offset + entry.function + std::mem::size_of::<usize>();

                (address, function, entry)
            })
    }
}
