#[panic_handler] // panicking behavior
fn panic(i: &core::panic::PanicInfo) -> ! {
    rprintln!("=== PANIC ===");

    if let Some(location) = i.location() {
        rprintln!("@ {}:{}", location.file(), location.line());
    }
    rprintln!("");

    // PanicInfo::message() is unstable so we have to debug-dump entire struct
    rprintln!("{:#?}", i);

    rprintln!("Hanging ...");
    loop {
        cortex_m::asm::bkpt();
    }
}
