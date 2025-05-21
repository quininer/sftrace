pub fn page_size() -> usize {
    unsafe {
        libc::sysconf(libc::_SC_PAGE_SIZE) as usize
    }
}

pub struct ScopeGuard<T, F: Fn(&mut T)>(pub T, pub F);

impl<T, F: Fn(&mut T)> Drop for ScopeGuard<T, F> {
    fn drop(&mut self) {
        (self.1)(&mut self.0);
    }
}

pub fn u64_is_zero(n: &u64) -> bool {
    *n == 0
}

pub fn u128_is_zero(n: &u128) -> bool {
    *n == 0
}

pub struct MProtect {
    flag: bool,
    addr: *mut u8,
    size: usize
}

impl MProtect {
    #[cfg(target_os = "linux")]
    pub unsafe fn unlock(addr: *mut u8, size: usize) -> MProtect {
        let succ = libc::mprotect(
            addr.cast(),
            size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        ) == 0;

        if !succ {
            eprintln!(
                "text segment {:?} unlock failed: {:?}",
                (addr, size),
                std::io::Error::last_os_error()
            );
        }

        MProtect {
            flag: succ,
            addr, size
        }
    }

    #[cfg(target_os = "macos")]
    pub unsafe fn unlock(addr: *mut u8, size: usize) -> MProtect {
        let ret = mach2::vm::mach_vm_protect(
            mach2::traps::mach_task_self(),
            addr as _,
            size as _,
            0,
            mach2::vm_prot::VM_PROT_READ | mach2::vm_prot::VM_PROT_WRITE | mach2::vm_prot::VM_PROT_COPY
        );
        let succ = ret == mach2::kern_return::KERN_SUCCESS;

        if !succ {
            eprintln!(
                "text segment {:?} unlock failed: {:?}",
                (addr, size), ret
            );            
        }

        MProtect {
            flag: succ,
            addr, size
        }         
    }
}

impl Drop for MProtect {
    fn drop(&mut self) {
        if self.flag {
            #[cfg(target_os = "linux")]
            unsafe {
                let ret = libc::mprotect(
                    self.addr.cast(),
                    self.size,
                    libc::PROT_READ | libc::PROT_EXEC
                );

                if ret != 0 {
                    eprintln!("text segment lock failed: {:?}", std::io::Error::last_os_error());
                }
            }

            #[cfg(target_os = "macos")]
            unsafe {
                let ret = mach2::vm::mach_vm_protect(
                    mach2::traps::mach_task_self(),
                    self.addr as _,
                    self.size as _,
                    0,
                    mach2::vm_prot::VM_PROT_READ | mach2::vm_prot::VM_PROT_EXECUTE
                );

                if ret != mach2::kern_return::KERN_SUCCESS {
                    eprintln!("text segment lock failed: {:?}", ret);
                }
            };
        }
    }
}
