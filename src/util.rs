pub fn thread_id() -> libc::pid_t {
    unsafe {
        libc::syscall(libc::SYS_gettid) as libc::pid_t
    }
}

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
