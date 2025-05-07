//! https://github.com/llvm/llvm-project/blob/llvmorg-20.1.4/compiler-rt/lib/xray/xray_trampoline_x86_64.S

use crate::events::{ record_entry, record_exit, record_tailcall };

#[repr(C)]
pub struct Args {
    pub r11: u64,
    pub r10: u64,
    
    pub r9: u64,
    pub r8: u64,
    pub rcx: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rdi: u64,

    pub xmm7: u128,
    pub xmm6: u128,
    pub xmm5: u128,
    pub xmm4: u128,
    pub xmm3: u128,
    pub xmm2: u128,
    pub xmm1: u128,
    pub xmm0: u128,
}

#[repr(C)]
pub struct ReturnValue {
    pub rax: u64,
    pub rdx: u64,
    pub xmm0: u128,
    pub xmm1: u128
}

#[unsafe(naked)]
pub unsafe extern "C" fn xray_entry() {
    std::arch::naked_asm!(
        "sub rsp, 0xc8",

        // float args
        "movdqu xmmword ptr [rsp+0xb8], xmm0",
        "movdqu xmmword ptr [rsp+0xa8], xmm1",
        "movdqu xmmword ptr [rsp+0x98], xmm2",
        "movdqu xmmword ptr [rsp+0x88], xmm3",
        "movdqu xmmword ptr [rsp+0x78], xmm4",
        "movdqu xmmword ptr [rsp+0x68], xmm5",
        "movdqu xmmword ptr [rsp+0x58], xmm6",
        "movdqu xmmword ptr [rsp+0x48], xmm7",

        // args
        "mov      qword ptr [rsp+0x40],  rdi",
        "mov      qword ptr [rsp+0x38],  rax",
        "mov      qword ptr [rsp+0x30],  rdx",
        "mov      qword ptr [rsp+0x28],  rsi",
        "mov      qword ptr [rsp+0x20],  rcx",
        "mov      qword ptr [rsp+0x18],   r8",
        "mov      qword ptr [rsp+0x10],   r9",

        // caller save
        "mov      qword ptr [rsp+0x08],  r10",
        "mov      qword ptr [rsp     ],  r11",        

        // child ip
        "mov rdi, qword ptr [rsp+0xc8]",

        // args
        "mov rsi, rsp",

        // align sp to 16B
        //
        // align to 8B then push 8B
        "and rsp, 0xfffffffffffffff8",

        // save original sp
        "push rsi",

        "call {0}",

        // restore rsp
        "pop rsp",

        // restore
        "movdqu xmm0, xmmword ptr [rsp+0xb8]",
        "movdqu xmm1, xmmword ptr [rsp+0xa8]",
        "movdqu xmm2, xmmword ptr [rsp+0x98]",
        "movdqu xmm3, xmmword ptr [rsp+0x88]",
        "movdqu xmm4, xmmword ptr [rsp+0x78]",
        "movdqu xmm5, xmmword ptr [rsp+0x68]",
        "movdqu xmm6, xmmword ptr [rsp+0x58]",
        "movdqu xmm7, xmmword ptr [rsp+0x48]",

        "mov     rdi,   qword ptr [rsp+0x40]",
        "mov     rax,   qword ptr [rsp+0x38]",
        "mov     rdx,   qword ptr [rsp+0x30]",
        "mov     rsi,   qword ptr [rsp+0x28]",
        "mov     rcx,   qword ptr [rsp+0x20]",
        "mov      r8,   qword ptr [rsp+0x18]",
        "mov      r9,   qword ptr [rsp+0x10]",

        "mov     r10,   qword ptr [rsp+0x08]",
        "mov     r11,   qword ptr [rsp     ]",

        "add rsp, 0xc8",
        
        "ret",
        sym record_entry,
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn xray_exit() {
    std::arch::naked_asm!(
        // return address already consume 8b
        "sub rsp, 0x30",

        // save original return values
        "movdqu xmmword ptr [rsp+0x20], xmm0",
        "movdqu xmmword ptr [rsp+0x10], xmm1",
        "mov      qword ptr [rsp+0x08],  rdx",
        "mov      qword ptr [rsp     ],  rax",

        // return value
        "mov rdi, rsp",

        // align sp to 16B
        //
        // align to 8B then push 8B
        "and rsp, 0xfffffffffffffff8",

        // save original sp
        "push rdi",

        "call {0}",

        "pop rsp",

        "mov     rax,   qword ptr [rsp     ]",
        "mov     rdx,   qword ptr [rsp+0x08]",
        "movdqu xmm0, xmmword ptr [rsp+0x10]",
        "movdqu xmm1, xmmword ptr [rsp+0x20]",
        
        "add rsp, 0x30",
        
        "ret",
        sym record_exit,
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn xray_tailcall() {
    std::arch::naked_asm!(
        "sub rsp, 0xc8",

        // float args
        "movdqu xmmword ptr [rsp+0xb8], xmm0",
        "movdqu xmmword ptr [rsp+0xa8], xmm1",
        "movdqu xmmword ptr [rsp+0x98], xmm2",
        "movdqu xmmword ptr [rsp+0x88], xmm3",
        "movdqu xmmword ptr [rsp+0x78], xmm4",
        "movdqu xmmword ptr [rsp+0x68], xmm5",
        "movdqu xmmword ptr [rsp+0x58], xmm6",
        "movdqu xmmword ptr [rsp+0x48], xmm7",

        // args
        "mov      qword ptr [rsp+0x40],  rdi",
        "mov      qword ptr [rsp+0x38],  rax",
        "mov      qword ptr [rsp+0x30],  rdx",
        "mov      qword ptr [rsp+0x28],  rsi",
        "mov      qword ptr [rsp+0x20],  rcx",
        "mov      qword ptr [rsp+0x18],   r8",
        "mov      qword ptr [rsp+0x10],   r9",

        // caller save
        "mov      qword ptr [rsp+0x08],  r10",
        "mov      qword ptr [rsp     ],  r11",        

        // child ip
        "mov rdi, qword ptr [rsp+0xc8]",

        // args
        "mov rsi, rsp",

        // align sp to 16B
        //
        // align to 8B then push 8B
        "and rsp, 0xfffffffffffffff8",

        // save original sp
        "push rsi",

        "call {0}",

        // restore rsp
        "pop rsp",

        // restore
        "movdqu xmm0, xmmword ptr [rsp+0xb8]",
        "movdqu xmm1, xmmword ptr [rsp+0xa8]",
        "movdqu xmm2, xmmword ptr [rsp+0x98]",
        "movdqu xmm3, xmmword ptr [rsp+0x88]",
        "movdqu xmm4, xmmword ptr [rsp+0x78]",
        "movdqu xmm5, xmmword ptr [rsp+0x68]",
        "movdqu xmm6, xmmword ptr [rsp+0x58]",
        "movdqu xmm7, xmmword ptr [rsp+0x48]",

        "mov     rdi,   qword ptr [rsp+0x40]",
        "mov     rax,   qword ptr [rsp+0x38]",
        "mov     rdx,   qword ptr [rsp+0x30]",
        "mov     rsi,   qword ptr [rsp+0x28]",
        "mov     rcx,   qword ptr [rsp+0x20]",
        "mov      r8,   qword ptr [rsp+0x18]",
        "mov      r9,   qword ptr [rsp+0x10]",

        "mov     r10,   qword ptr [rsp+0x08]",
        "mov     r11,   qword ptr [rsp     ]",

        "add rsp, 0xc8",
        
        "ret",
        sym record_tailcall,
    );
}
