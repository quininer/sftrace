#[unsafe(naked)]
pub unsafe extern "C" fn xray_entry() {
    std::arch::naked_asm!(
        "ret"
    );
}

#[unsafe(naked)]
pub unsafe extern "C" fn xray_exit() {
    std::arch::naked_asm!(
        "ret"
    );
}
