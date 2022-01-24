/// A simple strcpy implementation, when optimizations are enabled littlefs2
/// needs this.
#[no_mangle]
unsafe extern "C" fn strcpy(mut dest: *mut u8, mut src: *const u8) -> *mut u8 {
    let dest_copy = dest;

    loop {
        let b = src.read();
        dest.write(b);

        if b == 0 {
            break;
        }

        dest = dest.wrapping_add(1);
        src = src.wrapping_add(1);
    }

    dest_copy
}
