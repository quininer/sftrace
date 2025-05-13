//! https://github.com/llvm/llvm-project/blob/llvmorg-20.1.4/compiler-rt/lib/xray/xray_trampoline_x86_64.S

use serde::Serialize;
use crate::events;

#[derive(Serialize)]
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

#[derive(Serialize)]
#[repr(C)]
pub struct ReturnValue {
    pub rax: u64,
    pub rdx: u64,
    pub xmm0: u128,
    pub xmm1: u128
}

macro_rules! helper {
    (save args) => {
        concat!(
            // float args
            "movdqu xmmword ptr [rsp+0xb8], xmm0\n",
            "movdqu xmmword ptr [rsp+0xa8], xmm1\n",
            "movdqu xmmword ptr [rsp+0x98], xmm2\n",
            "movdqu xmmword ptr [rsp+0x88], xmm3\n",
            "movdqu xmmword ptr [rsp+0x78], xmm4\n",
            "movdqu xmmword ptr [rsp+0x68], xmm5\n",
            "movdqu xmmword ptr [rsp+0x58], xmm6\n",
            "movdqu xmmword ptr [rsp+0x48], xmm7\n",

            // args
            "mov      qword ptr [rsp+0x40],  rdi\n",
            "mov      qword ptr [rsp+0x38],  rax\n",
            "mov      qword ptr [rsp+0x30],  rdx\n",
            "mov      qword ptr [rsp+0x28],  rsi\n",
            "mov      qword ptr [rsp+0x20],  rcx\n",
            "mov      qword ptr [rsp+0x18],   r8\n",
            "mov      qword ptr [rsp+0x10],   r9\n",

            // caller save
            "mov      qword ptr [rsp+0x08],  r10\n",
            "mov      qword ptr [rsp     ],  r11\n",            
        )
    };
    (restore args) => {
        concat!(
            // restore
            "movdqu xmm0, xmmword ptr [rsp+0xb8]\n",
            "movdqu xmm1, xmmword ptr [rsp+0xa8]\n",
            "movdqu xmm2, xmmword ptr [rsp+0x98]\n",
            "movdqu xmm3, xmmword ptr [rsp+0x88]\n",
            "movdqu xmm4, xmmword ptr [rsp+0x78]\n",
            "movdqu xmm5, xmmword ptr [rsp+0x68]\n",
            "movdqu xmm6, xmmword ptr [rsp+0x58]\n",
            "movdqu xmm7, xmmword ptr [rsp+0x48]\n",

            "mov     rdi,   qword ptr [rsp+0x40]\n",
            "mov     rax,   qword ptr [rsp+0x38]\n",
            "mov     rdx,   qword ptr [rsp+0x30]\n",
            "mov     rsi,   qword ptr [rsp+0x28]\n",
            "mov     rcx,   qword ptr [rsp+0x20]\n",
            "mov      r8,   qword ptr [rsp+0x18]\n",
            "mov      r9,   qword ptr [rsp+0x10]\n",

            "mov     r10,   qword ptr [rsp+0x08]\n",
            "mov     r11,   qword ptr [rsp     ]\n",
        )
    };
    (save return) => {
        concat!(
            // save original return values
            "movdqu xmmword ptr [rsp+0x20], xmm0\n",
            "movdqu xmmword ptr [rsp+0x10], xmm1\n",
            "mov      qword ptr [rsp+0x08],  rdx\n",
            "mov      qword ptr [rsp     ],  rax\n",
        )
    };
    (restore return) => {
        concat!(
            "mov     rax,   qword ptr [rsp     ]\n",
            "mov     rdx,   qword ptr [rsp+0x08]\n",
            "movdqu xmm0, xmmword ptr [rsp+0x10]\n",
            "movdqu xmm1, xmmword ptr [rsp+0x20]\n",
        )
    }
}

macro_rules! build {
    (entry: $name:ident -> $sym:expr) => {
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            std::arch::naked_asm!(
                "sub rsp, 0xc8",

                helper!(save args),

                // child ip
                "mov rdi, qword ptr [rsp+0xc8]",

                // args
                "mov rsi, rsp",

                // align sp to 8B
                "and rsp, 0xfffffffffffffff8",

                // save original sp and push to 16B
                "push rsi",

                "call {0}",

                // restore rsp
                "pop rsp",

                helper!(restore args),

                "add rsp, 0xc8",
        
                "ret",
                sym $sym,
            );
        }        
    };
    (exit: $name:ident -> $sym:expr) => {
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            std::arch::naked_asm!(
                // return address already consume 8b
                "sub rsp, 0x30",

                helper!(save return),

                // return value
                "mov rdi, rsp",

                // align sp to 8B
                "and rsp, 0xfffffffffffffff8",

                // save original sp and push to 16B
                "push rdi",

                "call {0}",

                "pop rsp",

                helper!(restore return),
        
                "add rsp, 0x30",
        
                "ret",
                sym $sym,
            );
        }
    }
}

build!(entry: xray_entry     -> events::record_entry);
build!(entry: xray_entry_log -> events::record_entry_log);
build!(entry: xray_tailcall  -> events::record_tailcall);
build!(exit : xray_exit      -> events::record_exit);
build!(exit : xray_exit_log  -> events::record_exit_log);
