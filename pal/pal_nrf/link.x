INCLUDE link.x
STORAGE_SIZE = 65536;

SECTIONS {
    # Storage must be aligned on erase block size (4096), otherwise firmware
    # could corrupt itself when erase/write cycle got interrupted.
    #
    .storage (LENGTH(FLASH) - STORAGE_SIZE) (NOLOAD) : {
        PROVIDE(__persistent_storage_start = .);
        FILL(0xffff);
        . += STORAGE_SIZE;
        PROVIDE(__persistent_storage_end = .);
    } > FLASH
}

ASSERT(ORIGIN(FLASH) == 0, "Flash origin is not at 0x0");
ASSERT(STORAGE_SIZE % 4096 == 0, "Persistent storage size not multiple of 4096");
ASSERT(__persistent_storage_start % 4096 == 0, "Persistent storage size is not aligned");
