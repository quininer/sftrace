use std::io::Write;
use std::time::Instant;
use std::cell::RefCell;
use std::sync::LazyLock;
use std::sync::atomic::{ self, AtomicU32 };
use crate::arch::{ Args, ReturnValue };
use crate::{layout::*, SETUP_THREAD, SETUP_THREAD_ONLY};
use crate::{ OUTPUT, FuncId };


struct Local {
    tid: Option<u32>,
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
        func_id: u32,
        args: Option<&Args>,
        return_value: Option<&ReturnValue>,
        alloc_event: Option<&AllocEvent>,
    ) {
        if SETUP_THREAD_ONLY.load(atomic::Ordering::Relaxed) && !SETUP_THREAD.get() {
           return;
        }

        static NOW: LazyLock<Instant> = LazyLock::new(Instant::now);

        const CAP: usize = 4 * 1024;

        // Uninitialized, ignored
        if OUTPUT.get().is_none() {
           return; 
        }

        let func_id = FuncId(func_id);
        let (func_id, flag) = func_id.unpack();
        
        let event: Event<&Args, &ReturnValue, &AllocEvent> = Event {
            kind, func_id, alloc_event,
            time: dur2u64(NOW.elapsed()),
            tid: *self.tid.get_or_insert_with(|| {
                // TODO use std::thread::Thread.id().as_u64()
                static THREAD_ID: AtomicU32 = AtomicU32::new(0);

                THREAD_ID.fetch_add(1, atomic::Ordering::Relaxed)
            }),
            args: args.filter(|_| flag.contains(FuncFlag::LOG)),
            return_value: return_value.filter(|_| flag.contains(FuncFlag::LOG)),
        };
        cbor4ii::serde::to_writer(&mut self.line, &event).unwrap();

        if self.buf.capacity() == 0 {
            self.reserve(CAP);
        }

        if !self.buf.is_empty() && self.buf.len() + self.line.len() > CAP {
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

pub extern "C" fn record_entry(func_id: u32, args: &Args) {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.record(Kind::ENTRY, func_id, Some(args), None, None);
        }
    });
}

pub extern "C" fn record_exit(func_id: u32, return_value: &ReturnValue) {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.record(Kind::EXIT, func_id, None, Some(return_value), None);
        }
    });    
}

pub extern "C" fn record_tailcall(func_id: u32) {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.record(Kind::TAIL_CALL, func_id, None, None, None);
        }
    });    
}

pub fn record_alloc(
    kind: u8,
    size: usize,
    align: usize,
    ptr: *mut u8
) {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            let kind = match kind {
                1 => Kind::ALLOC,
                2 => Kind::DEALLOC,
                3 => Kind::REALLOC_ALLOC,
                4 => Kind::REALLOC_DEALLOC,
                _ => panic!()
            };
        
            let event = AllocEvent {
                size: size as u64,
                align: align as u64,
                ptr: ptr as usize as u64
            };
        
            local.record(kind, 0, None, None, Some(&event));
        }
    });
}
