//! https://github.com/namhyung/uftrace/blob/master/arch/x86_64/xray.S

use crate::events::{ record_entry, record_exit };

#[repr(C)]
pub struct Args {
    pub r9: u64,
    pub r8: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
}

#[repr(C)]
pub struct ReturnValue {
    pub rax: u64,
    pub rdx: u64,
    pub xmm0: [u8; 16]
}

#[unsafe(naked)]
pub unsafe extern "C" fn xray_entry() {
    std::arch::naked_asm!(
        "sub rsp, 0x30",

        "mov qword ptr [rsp+0x28], rdi",
        "mov qword ptr [rsp+0x20], rsi",
        "mov qword ptr [rsp+0x18], rdx",
        "mov qword ptr [rsp+0x10], rcx",
        "mov qword ptr [rsp+0x08],  r8",
        "mov qword ptr [rsp     ],  r9",

        // child ip
        "mov rsi, qword ptr [rsp+0x30]",

        // parent location
        "lea rdi, [rsp+0x38]",

        // args
        "mov rdx, rsp",

        // align sp to 16b
        "and rsp, 0xfffffffffffffff0",
        "push rdx",

        // save rax (implicit argument for variadic functions)
        "push rax",

        "call {0}",

        "pop rax",
        "pop rdx",
        "mov rsp, rdx",

        "mov  r9, qword ptr [rsp]",
        "mov  r8, qword ptr [rsp+0x08]",
        "mov rcx, qword ptr [rsp+0x10]",
        "mov rdx, qword ptr [rsp+0x18]",
        "mov rsi, qword ptr [rsp+0x20]",
        "mov rdi, qword ptr [rsp+0x28]",

        "add rsp, 0x30",
        
        "ret",
        sym record_entry,
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn xray_exit() {
    std::arch::naked_asm!(
        // return address already consume 8b
        "sub rsp, 0x28",

        "mov      qword ptr [rsp+0x20],  rdi",
        // save original return values
        "movdqu xmmword ptr [rsp+0x10], xmm0",
        "mov      qword ptr [rsp+0x08],  rdx",
        "mov      qword ptr [rsp     ],  rax",

        // return value
        "mov rdi, rsp",

        // align sp to 16b
        "and rsp, 0xfffffffffffffff0",
        "sub rsp, 0x10",

        // save original sp
        "mov qword ptr [rsp], rdi",

        "call {0}",

        "mov rsp, qword ptr [rsp]",

        "mov     rax,   qword ptr [rsp     ]",
        "mov     rdx,   qword ptr [rsp+0x08]",
        "movdqu xmm0, xmmword ptr [rsp+0x10]",
        "mov     rdi,   qword ptr [rsp+0x20]",
        
        "add rsp, 0x28",
        
        "ret",
        sym record_exit,
    );
}
