use std::ptr;
use std::io::Write;
use std::time::Instant;
use std::cell::RefCell;
use std::sync::LazyLock;
use crate::util::thread_id;
use crate::arch::{ Args, ReturnValue };
use crate::layout::*;
use crate::OUTPUT;


struct Local {
    tid: Option<libc::pid_t>,
    buf: Vec<u8>,
    line: Vec<u8>,
}

thread_local!{
    static LOCAL: RefCell<Local> = const {
        RefCell::new(Local {
            tid: None,
            buf: Vec::new(),
            line: Vec::new()
        })
    };
}

impl Drop for Local {
    fn drop(&mut self) {
        self.flush();        
    }
}

fn dur2u64(dur: std::time::Duration) -> u64 {
    dur.as_nanos() as u64
}

impl Local {
    #[inline]
    pub fn record(
        &mut self,
        kind: Kind,
        child_ip: *const u8,
        args: Option<&Args>,
        return_value: Option<&ReturnValue>,
        alloc_event: Option<&AllocEvent>,
    ) {
        static NOW: LazyLock<Instant> = LazyLock::new(Instant::now);

        const CAP: usize = 4 * 1024;

        // Uninitialized, ignored
        if OUTPUT.get().is_none() {
           return; 
        }
        
        let event: Event<&Args, &ReturnValue, &AllocEvent> = Event {
            kind,
            child_ip: (child_ip as u64),
            time: dur2u64(NOW.elapsed()),
            tid: (*self.tid.get_or_insert_with(thread_id)),
            args, return_value, alloc_event
        };
        cbor4ii::serde::to_writer(&mut self.line, &event).unwrap();

        if self.buf.capacity() == 0 {
            self.reserve(CAP);
        }

        if self.buf.len() != 0 && self.buf.len() + self.line.len() > CAP {
            self.flush();
        }

        self.buf.append(&mut self.line);
    }

    #[cold]
    fn reserve(&mut self, n: usize) {
        self.buf.reserve(n);
    }

    pub fn flush(&mut self) {
        if let Some(mut output) = OUTPUT.get() {
            // We assume that writes are atomic (<= 4k)
            output.write_all(&self.buf).unwrap();
            self.buf.clear();
        }
    }
}

pub fn flush_current_thread() {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.flush();
        }
    });
}

pub extern "C" fn record_entry(child: *const u8) {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.record(Kind::ENTRY, child, None, None, None);
        }
    });
}

pub extern "C" fn record_exit() {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.record(Kind::EXIT, ptr::null(), None, None, None);
        }
    });    
}

pub extern "C" fn record_tailcall() {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.record(Kind::TAIL_CALL, ptr::null(), None, None, None);
        }
    });    
}

pub extern "C" fn record_entry_log(child: *const u8, args: &Args) {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.record(Kind::ENTRY, child, Some(args), None, None);
        }
    });
}

pub extern "C" fn record_exit_log(return_value: &ReturnValue) {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.record(Kind::EXIT, ptr::null(), None, Some(return_value), None);
        }
    });    
}

pub fn record_alloc(
    kind: u8,
    old_size: usize,
    new_size: usize,
    align: usize,
    old_ptr: *mut u8,
    new_ptr: *mut u8
) {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            let kind = match kind {
                1 => Kind::ALLOC,
                2 => Kind::DEALLOC,
                3 => Kind::REALLOC,
                _ => panic!()
            };
        
            let event = AllocEvent {
                old_size: old_size as u64,
                new_size: new_size as u64,
                align: align as u64,
                old_ptr: old_ptr as usize as u64,
                new_ptr: new_ptr as usize as u64
            };
        
            local.record(kind, ptr::null(), None, None, Some(&event));
        }
    });
}
