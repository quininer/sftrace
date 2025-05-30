use std::alloc::GlobalAlloc;

unsafe extern "C" {
    fn sftrace_setup(
        entry_slot: unsafe extern "C" fn(),
        exit_slot: unsafe extern "C" fn(),
        tailcall_slot: unsafe extern "C" fn(),        
    );

    fn sftrace_alloc_event(
        kind: u8,
        size: usize,
        align: usize,
        ptr: *mut u8    
    );    
}

#[cfg(target_arch = "x86_64")]
macro_rules! build_slot {
    ( $( $name:ident );* $( ; )? ) => {
        $(
            build_slot!(@$name);
        )*
    };
    ( @ $name:ident ) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            // ret + nop * 15
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

#[cfg(target_arch = "aarch64")]
macro_rules! build_slot {
    ( $( $name:ident );* $( ; )? ) => {
        $(
            build_slot!(@$name);
        )*
    };
    ( @ $name:ident ) => {
        unsafe extern "C" fn $name() {
            // empty
        }
    };
}

build_slot! {
    sftrace_entry_slot;
    sftrace_exit_slot;
    sftrace_tailcall_slot;
}

#[inline(always)]
pub unsafe fn setup() {
    unsafe {
        sftrace_setup(
            sftrace_entry_slot,
            sftrace_exit_slot,
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
            sftrace_alloc_event(1, layout.size(), layout.align(), v);
            v
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe {
            sftrace_alloc_event(2, layout.size(), layout.align(), ptr);
            std::alloc::System.dealloc(ptr, layout);           
        }
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        unsafe {
            let v = std::alloc::System.alloc_zeroed(layout);
            sftrace_alloc_event(1, layout.size(), layout.align(), v);
            v
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        unsafe {
            sftrace_alloc_event(4, layout.size(), layout.align(), ptr);
            let v = std::alloc::System.realloc(ptr, layout, new_size);
            sftrace_alloc_event(3, new_size, layout.align(), v);
            v            
        }
    }
}
