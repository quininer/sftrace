unsafe extern "C" {
    fn sftrace_setup(
        entry_slot: unsafe extern "C" fn(),
        exit_slot: unsafe extern "C" fn(),
        tailcall_slot: unsafe extern "C" fn(),
    );
}

#[unsafe(naked)]
unsafe extern "C" fn sftrace_entry_slot() {
    std::arch::naked_asm!(
        "ret",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
    );
}

#[unsafe(naked)]
unsafe extern "C" fn sftrace_exit_slot() {
    std::arch::naked_asm!(
        "ret",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
    );    
}

#[unsafe(naked)]
unsafe extern "C" fn sftrace_tailcall_slot() {
    std::arch::naked_asm!(
        "ret",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
        "nop",
    );    
}

#[inline(always)]
pub fn setup() {
    unsafe {
        sftrace_setup(
            sftrace_entry_slot,
            sftrace_exit_slot,
            sftrace_tailcall_slot
        );
    }
}
