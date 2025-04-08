use std::sync::Mutex;
use std::cell::RefCell;
use quanta::Instant;
use crate::util::thread_id;


pub(crate) struct GlobalEventList;

#[derive(Debug)]
pub(crate) struct Call {
    pub addr: Pointer,
    pub time: Instant,
    pub tid: libc::pid_t,
    pub depth: u16,
    pub r#return: bool,
}

#[derive(Debug)]
pub struct Pointer(*const u8);

unsafe impl Send for Pointer {}

struct Local {
    tid: Option<libc::pid_t>,
    sp: *const u8,
    depth: u16,
    events: Vec<Call>
}

static GLOBAL: Mutex<Vec<Vec<Call>>> = Mutex::new(Vec::new());

thread_local!{
    static LOCAL: RefCell<Local> = const {
        RefCell::new(Local {
            tid: None,
            sp: std::ptr::null(),
            depth: 0,
            events: Vec::new()
        })
    };
}

impl Drop for Local {
    fn drop(&mut self) {
        let mut local = std::mem::take(&mut self.events);
        local.shrink_to_fit();
        let mut global = GLOBAL.lock().unwrap();
        global.push(local);
    }
}

impl GlobalEventList {
    pub fn record(&self, callee: *const u8, sp: *const u8) {
        LOCAL.with_borrow_mut(|local| {
            let prev_sp = std::mem::replace(&mut local.sp, sp);
            let r#return = prev_sp > sp;

            let call = Call {
                addr: Pointer(callee),
                time: Instant::now(),
                tid: *local.tid.get_or_insert_with(thread_id),
                depth: local.depth,
                r#return
            };

            match r#return {
                false => local.depth += 1,
                true => local.depth -= 1
            }
            local.events.push(call);
        });
    }

    pub fn take(&self) -> Vec<Vec<Call>> {
        let mut list = GLOBAL.lock().unwrap();
        std::mem::take(&mut *list)
    }
}
