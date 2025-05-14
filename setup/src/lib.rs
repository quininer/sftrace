use std::alloc::GlobalAlloc;

unsafe extern "C" {
    fn sftrace_setup(
        entry_slot: unsafe extern "C" fn(),
        entry_log_slot: unsafe extern "C" fn(),
        exit_slot: unsafe extern "C" fn(),
        exit_log_slot: unsafe extern "C" fn(),
        tailcall_slot: unsafe extern "C" fn(),        
    );

    fn sftrace_alloc_event(
        kind: u8,
        old_size: usize,
        new_size: usize,
        align: usize,
        old_ptr: *mut u8,
        new_ptr: *mut u8    
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
pub unsafe fn setup() {
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

pub struct SftraceAllocator<A: GlobalAlloc>(pub A);

unsafe impl<A: GlobalAlloc> GlobalAlloc for SftraceAllocator<A> {
    #[inline]
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        unsafe {
            let v = std::alloc::System.alloc(layout);
            sftrace_alloc_event(1, 0, layout.size(), layout.align(), std::ptr::null_mut(), v);
            v
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe {
            sftrace_alloc_event(2, layout.size(), 0, layout.align(), ptr, std::ptr::null_mut());
            std::alloc::System.dealloc(ptr, layout);           
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        unsafe {
            let v = std::alloc::System.alloc_zeroed(layout);
            sftrace_alloc_event(1, 0, layout.size(), layout.align(), std::ptr::null_mut(), v);
            v
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        unsafe {
            let v = std::alloc::System.realloc(ptr, layout, new_size);
            sftrace_alloc_event(3, layout.size(), new_size, layout.align(), ptr, v);
            v            
        }
    }
}
