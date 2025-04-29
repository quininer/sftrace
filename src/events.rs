use std::ptr;
use std::io::Write;
use std::sync::LazyLock;
use std::cell::RefCell;
use quanta::Instant;
use zerocopy::IntoBytes;
use crate::util::thread_id;
use crate::arch::{ Args, ReturnValue };
use crate::layout::*;


struct Local {
    tid: Option<libc::pid_t>,
    events: Vec<Event>
}

thread_local!{
    static LOCAL: RefCell<Local> = const {
        RefCell::new(Local {
            tid: None,
            events: Vec::new()
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

        const _: () = [(); 1][std::mem::size_of::<Event>() - 29];
        const CAP: usize = 4 * 1024 / std::mem::size_of::<Event>();
        
        let event = Event {
            kind,
            parent_ip: (parent_ip as u64).into(),
            child_ip: (child_ip as u64).into(),
            time: dur2u64(NOW.elapsed()).into(),
            tid: (*self.tid.get_or_insert_with(thread_id)).into(),
        };

        if self.events.capacity() == 0 {
            self.reserve(CAP);
        }

        if self.events.len() == CAP {
            self.flush();
        }

        self.events.push(event);
    }

    #[cold]
    pub fn reserve(&mut self, n: usize) {
        self.events.reserve(n);
    }

    pub fn flush(&mut self) {
        use crate::OUTPUT;

        let mut output = OUTPUT.get().unwrap();

        // We assume that writes are atomic (<= 4k)
        output.write_all(self.events.as_bytes()).unwrap();
        self.events.clear();
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
