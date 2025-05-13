unsafe extern "C" {
    fn sftrace_setup(
        entry_slot: unsafe extern "C" fn(),
        entry_log_slot: unsafe extern "C" fn(),
        exit_slot: unsafe extern "C" fn(),
        exit_log_slot: unsafe extern "C" fn(),
        tailcall_slot: unsafe extern "C" fn(),        
    );
}

macro_rules! build_slot {
    ( $( $name:ident );* $( ; )? ) => {
        $(
            build_slot!(@$name);
        )*
    };
    ( @ $name:ident ) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
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
    };
}

build_slot! {
    sftrace_entry_slot;
    sftrace_entry_log_slot;
    sftrace_exit_slot;
    sftrace_exit_log_slot;
    sftrace_tailcall_slot;
}

#[inline(always)]
pub fn setup() {
    unsafe {
        sftrace_setup(
            sftrace_entry_slot,
            sftrace_entry_log_slot,
            sftrace_exit_slot,
            sftrace_exit_log_slot,
            sftrace_tailcall_slot
        );
    }
}
