#[cfg_attr(target_arch = "x86_64", path = "arch/x86_64.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/aarch64.rs")]
mod sys;

pub use sys::*;

const _ASSERT_ARCH: () = if !cfg!(target_pointer_width = "64") {
    panic!("64bit only")
};
