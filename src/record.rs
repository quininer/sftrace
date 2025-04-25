pub unsafe extern "C" fn xray_entry() {
    println!("entry");
}

pub unsafe extern "C" fn xray_exit() {
    println!("exit");
}
