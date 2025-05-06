use std::ptr;
use std::io::Write;
use std::sync::LazyLock;
use std::cell::RefCell;
use quanta::Instant;
use crate::util::thread_id;
use crate::arch::{ Args, ReturnValue };
use crate::layout::*;


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
    pub fn record(&mut self, kind: Kind, parent_ip: *const u8, child_ip: *const u8) {
        static NOW: LazyLock<Instant> = LazyLock::new(Instant::now);

        const CAP: usize = 4 * 1024;
        
        let event = Event {
            kind,
            parent_ip: (parent_ip as u64),
            child_ip: (child_ip as u64),
            time: dur2u64(NOW.elapsed()),
            tid: (*self.tid.get_or_insert_with(thread_id)),
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
        use crate::OUTPUT;

        let mut output = OUTPUT.get().unwrap();

        // We assume that writes are atomic (<= 4k)
        output.write_all(&self.buf).unwrap();
        self.buf.clear();
    }
}

pub fn flush_current_thread() {
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.flush();
        }
    });
}

pub extern "C" fn record_entry(parent: *const u8, child: *const u8, _args: &Args) {
    LOCAL.with_borrow_mut(|local| {
        local.record(Kind::ENTRY, parent, child);
    });
}

pub extern "C" fn record_exit(_return_value: &ReturnValue) {
    LOCAL.with_borrow_mut(|local| {
        local.record(Kind::EXIT, ptr::null(), ptr::null());
    });    
}
