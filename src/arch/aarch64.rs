//! https://github.com/llvm/llvm-project/blob/llvmorg-20.1.5/compiler-rt/lib/xray/xray_trampoline_AArch64.S

use std::ptr;
use std::sync::atomic::{ self, AtomicU32 };
use serde::Serialize;
use crate::events;
use crate::util::{ u64_is_zero, u128_is_zero };

#[derive(Serialize)]
#[repr(C)]
pub struct Args {
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x8: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x0: u64,

    #[serde(skip_serializing_if = "u128_is_zero")]
    pub q6: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub q7: u128,    
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub q4: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub q5: u128,   
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub q2: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub q3: u128, 
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub q0: u128,
    #[serde(skip_serializing_if = "u128_is_zero")]
    pub q1: u128,
    
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x7: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x30: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x5: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x6: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x3: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x4: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x1: u64,
    #[serde(skip_serializing_if = "u64_is_zero")]
    pub x2: u64,
}

pub type ReturnValue = Args;

macro_rules! helper {
    (save args) => {
        concat!(
            "stp x1, x2,  [sp, #-16]!\n",
            "stp x3, x4,  [sp, #-16]!\n",
            "stp x5, x6,  [sp, #-16]!\n",
            "stp x7, x30, [sp, #-16]!\n",
            "stp q0, q1,  [sp, #-32]!\n",
            "stp q2, q3,  [sp, #-32]!\n",
            "stp q4, q5,  [sp, #-32]!\n",
            "stp q6, q7,  [sp, #-32]!\n",
            // x8 is the indirect result register and needs to be preserved for the body of the function to use.
            "stp x8, x0,  [sp, #-16]!\n",
        )
    };
    (restore args) => {
        concat!(
            "ldp x8, x0,  [sp], #16\n",
            "ldp q6, q7,  [sp], #32\n",
            "ldp q4, q5,  [sp], #32\n",
            "ldp q2, q3,  [sp], #32\n",
            "ldp q0, q1,  [sp], #32\n",
            "ldp x7, x30, [sp], #16\n",
            "ldp x5, x6,  [sp], #16\n",
            "ldp x3, x4,  [sp], #16\n",
            "ldp x1, x2,  [sp], #16\n",            
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
                helper!(save args),

                "mov w0, w17",
                "mov x1, sp",

                "bl {0}",

                helper!(restore args),
                "ret",

                sym $sym,
            );
        }        
    };
    (exit: $name:ident -> $sym:expr) => {
        build!(entry: $name -> $sym);
    }
}

build!(entry: xray_entry     -> events::record_entry);
build!(exit : xray_exit      -> events::record_exit);
build!(entry: xray_tailcall  -> events::record_tailcall);

pub(crate) unsafe fn patch_slot(slot: *mut u8, target: usize) {
    const LDR_X16_8:  u32 = 0x58000050; // LDR ip0 #8
    const BR_X16:     u32 = 0xD61F0200; // BR ip0

    let addr = slot.cast::<u32>();

    addr.add(1).write(BR_X16);
    addr.add(2).cast::<u64>().write(target as u64);
    AtomicU32::from_ptr(addr)
        .store(LDR_X16_8, atomic::Ordering::Release);
}

// https://github.com/llvm/llvm-project/blob/llvmorg-20.1.5/compiler-rt/lib/xray/xray_AArch64.cpp#L33
unsafe fn patch_sled(address: usize, idx: u32, slot: unsafe extern "C" fn()) {
    const STP_X0_X30_SP_M16E: u32 = 0xA9BF7BE0; // STP X0, X30, [SP, #-16]!
    const LDR_W17_12:         u32 = 0x18000071; // LDR w17, #12
    const BL_0:               u32 = 0x94000000; // BL #0
    const B_16:               u32 = 0x14000004; // B #16
    const LDP_X0_X30_SP_16:   u32 = 0xA8C17BE0; // LDP X0, X30, [SP], #16

    fn sign_extend26(data: u32) -> u32 {
        let n = 32 - 26;
        
        (data << n) >> n
    }

    let trampoline = slot as usize;

    let offset = (trampoline as isize) - (address + 8) as isize;
    let offset: i32 = offset.try_into().unwrap();
    let offset = offset >> 2; // div 4

    if offset.abs() > 1 << 25 {
        panic!("offset greater than +/-128M: {:x}", offset);
    }

    let bl_offset = BL_0 | sign_extend26(offset as u32);

    let addr = ptr::null_mut::<u32>().with_addr(address);

    unsafe {
        addr.add(1).write(LDR_W17_12);
        addr.add(2).write(bl_offset);
        addr.add(3).write(B_16);
        addr.add(4).write(idx);
        addr.add(7).write(LDP_X0_X30_SP_16);
        AtomicU32::from_ptr(addr.cast())
            .store(STP_X0_X30_SP_M16E, atomic::Ordering::Release);
    }

    unsafe {
        clear_cache::clear_cache(addr, addr.add(7));
    }
}

pub(crate) unsafe fn patch_entry(address: usize, func_id: u32, slot: unsafe extern "C" fn()) {
    patch_sled(address, func_id, slot);
}

pub(crate) unsafe fn patch_exit(address: usize, func_id: u32, slot: unsafe extern "C" fn()) {
    patch_sled(address, func_id, slot);
}

pub(crate) unsafe fn patch_tailcall(address: usize, func_id: u32, slot: unsafe extern "C" fn()) {
    patch_sled(address, func_id, slot);
}
