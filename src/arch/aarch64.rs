//! https://github.com/llvm/llvm-project/blob/llvmorg-20.1.5/compiler-rt/lib/xray/xray_trampoline_AArch64.S

use std::ptr;
use std::sync::atomic::{ self, AtomicU16 };
use serde::Serialize;
use crate::events;
use crate::util::{ u64_is_zero, u128_is_zero };

#[derive(Serialize)]
#[repr(C)]
pub struct Args {
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub r11: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub r10: u64,
    
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub r9: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub r8: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub rcx: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub rsi: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub rdx: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub rax: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub rdi: u64,

    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm7: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm6: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm5: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm4: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm3: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm2: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm1: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm0: u128,
}

#[derive(Serialize)]
#[repr(C)]
pub struct ReturnValue {
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub rax: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub rdx: u64,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm0: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub xmm1: u128
}

macro_rules! helper {
    (save args) => {
        concat!(
            "stp x1, x2, [sp, #-16]!",
            "stp x3, x4, [sp, #-16]!",
            "stp x5, x6, [sp, #-16]!",
            "stp x7, x30, [sp, #-16]!",
            "stp q0, q1, [sp, #-32]!",
            "stp q2, q3, [sp, #-32]!",
            "stp q4, q5, [sp, #-32]!",
            "stp q6, q7, [sp, #-32]!",
  // x8 is the indirect result register and needs to be preserved for the body of the function to use.
            "stp x8, x0, [sp, #-16]!",
        )
    };
    (restore args) => {
        concat!(
            "ldp x8, x0, [sp], #16",
            "ldp q6, q7, [sp], #32",
            "ldp q4, q5, [sp], #32",
            "ldp q2, q3, [sp], #32",
            "ldp q0, q1, [sp], #32",
            "ldp x7, x30, [sp], #16",
            "ldp x5, x6, [sp], #16",
            "ldp x3, x4, [sp], #16",
            "ldp x1, x2, [sp], #16",            
        )
    };
    (save return) => {
        helper!(save args)
    };
    (restore return) => {
        helper!(restore args)
    }
}

macro_rules! build {
    (entry: $name:ident -> $sym:expr) => {
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            std::arch::naked_asm!(
                "nop"
            );
        }        
    };
    (exit: $name:ident -> $sym:expr) => {
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            std::arch::naked_asm!(
                "nop"
            );
        }
    }
}

build!(entry: xray_entry     -> events::record_entry);
build!(exit : xray_exit      -> events::record_exit);
build!(entry: xray_tailcall  -> events::record_tailcall);

pub(crate) unsafe fn patch_slot(slot: *mut u8, target: usize) {
    const TRAMPOLINE: [u8; 8] = [0x3e, 0xff, 0x25, 0x01, 0x00, 0x00, 0x00, 0xcc];

    // TODO support more arch
    assert!(cfg!(target_arch = "x86_64"));    

    slot.copy_from_nonoverlapping(TRAMPOLINE.as_ptr(), TRAMPOLINE.len());
    slot.byte_add(TRAMPOLINE.len()).cast::<u64>().write(target as u64);
}

// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/compiler-rt/lib/xray/xray_x86_64.cpp#L123
pub(crate) unsafe fn patch_entry(address: usize, idx: u32, slot: unsafe extern "C" fn()) {
    const CALL_OP_CODE: u8 = 0xe8;
    const MOV_R10_SEQ: u16 = 0xba41;

    // TODO support more arch
    assert!(cfg!(target_arch = "x86_64"));
    
    let trampoline = slot as usize;

    let offset = (trampoline as isize) - (address + 11) as isize;
    let offset = offset.try_into().unwrap();

    let addr = ptr::null_mut::<u8>().with_addr(address);

    unsafe {
        addr.byte_add(2).cast::<u32>().write(idx);
        addr.byte_add(6).write(CALL_OP_CODE);
        addr.byte_add(7).cast::<i32>().write(offset);
        AtomicU16::from_ptr(addr.cast())
            .store(MOV_R10_SEQ, atomic::Ordering::Release);
    }
}

pub(crate) unsafe fn patch_exit(address: usize, func_id: u32, slot: unsafe extern "C" fn()) {
    const JMP_OP_CODE: u8 = 0xe9;
    const MOV_R10_SEQ: u16 = 0xba41;

    // TODO support more arch
    assert!(cfg!(target_arch = "x86_64"));
    
    let trampoline = slot as usize;

    let offset = (trampoline as isize) - (address + 11) as isize;
    let offset = offset.try_into().unwrap();

    let addr = ptr::null_mut::<u8>().with_addr(address);

    unsafe {
        addr.byte_add(2).cast::<u32>().write(func_id);
        addr.byte_add(6).write(JMP_OP_CODE);
        addr.byte_add(7).cast::<i32>().write(offset);
        AtomicU16::from_ptr(addr.cast())
            .store(MOV_R10_SEQ, atomic::Ordering::Release);
    }
}

// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.2/compiler-rt/lib/xray/xray_x86_64.cpp#L224
pub(crate) unsafe fn patch_tailcall(address: usize, func_id: u32, slot: unsafe extern "C" fn()) {
    patch_entry(address, func_id, slot);
}
