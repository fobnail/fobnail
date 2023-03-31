INCLUDE link.x

# MUST be kept in sync with PERSISTENT_STORAGE_SIZE constant from store.rs
STORAGE_SIZE = 131072;
STACK_SIZE = 90112;

SECTIONS {
    # Storage must be aligned on erase block size (4096), otherwise firmware
    # could corrupt itself when erase/write cycle got interrupted.
    #
    .storage (LENGTH(FLASH) - STORAGE_SIZE) : {
        PROVIDE(__persistent_storage_start = .);
        FILL(0xffff);
        . += STORAGE_SIZE;
        PROVIDE(__persistent_storage_end = .);
    } > FLASH
}

SECTIONS {
    _stack_start = ORIGIN(RAM) + STACK_SIZE;
    .stack (NOLOAD) : {
        . += STACK_SIZE;
    } > RAM
}
INSERT BEFORE .data

ASSERT(ORIGIN(FLASH) == 0, "Flash origin is not at 0x0");
ASSERT(STORAGE_SIZE % 4096 == 0, "Persistent storage size not multiple of 4096");
ASSERT(__persistent_storage_start % 4096 == 0, "Persistent storage size is not aligned");
