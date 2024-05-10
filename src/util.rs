pub fn thread_id() -> libc::pid_t {
    unsafe {
        libc::syscall(libc::SYS_gettid) as libc::pid_t
    }
}
