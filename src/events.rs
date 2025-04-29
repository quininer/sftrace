use std::io::Write;
use std::ptr;
use std::sync::LazyLock;
use std::cell::RefCell;
use quanta::Instant;
use zerocopy::*;
use crate::util::thread_id;
use crate::arch::{ Args, ReturnValue };


#[derive(IntoBytes, Immutable, Unaligned)]
#[repr(C)]
pub struct Metadata {
    pub sign: [u8; 8],
    pub base: U64<LE>,
}

pub const SIGN: &[u8; 8] = b"sf\0trace";

#[derive(IntoBytes, Immutable, Unaligned)]
#[repr(C)]
pub struct Event {
    pub parent_ip: U64<LE>,
    pub child_ip: U64<LE>,
    pub time: U64<LE>,
    pub tid: I32<LE>,
    pub kind: Kind,
}

#[derive(IntoBytes, Immutable, Unaligned)]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Kind(u8);

impl Kind {
    pub const ENTRY: Kind = Kind(1);
    pub const EXIT: Kind = Kind(2);

    // malloc/free and more ...
}

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
    let secs = dur.as_secs();
    let millis = dur.subsec_millis() as u64;
    secs.saturating_mul(1000) + millis
}

impl Local {
    pub fn record(&mut self, kind: Kind, parent_ip: *const u8, child_ip: *const u8) {
        static NOW: LazyLock<Instant> = LazyLock::new(Instant::now);
        
        let call = Event {
            kind,
            parent_ip: U64::new(parent_ip as u64),
            child_ip: U64::new(child_ip as u64),
            time: U64::new(dur2u64(NOW.elapsed())),
            tid: I32::new(*self.tid.get_or_insert_with(thread_id)),
        };

        if self.events.capacity() == 0 {
            self.events.reserve(4 * 1024);
        }

        if self.events.len() == 4 * 1024 {
            self.flush();
        }

        self.events.push(call);
    }

    pub fn flush(&mut self) {
        use crate::OUTPUT;

        let mut output = OUTPUT.get().unwrap();
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
