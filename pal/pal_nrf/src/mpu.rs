use core::mem::MaybeUninit;

use cortex_mpu::{
    cortex_m4::{CachePolicy, MemoryAttributes, Region},
    ArrayVec, FullAccessPermissions, Size, Subregions,
};

pub unsafe fn init_protection() {
    let mut regions = ArrayVec::new();
    // Flash region
    regions.push(Region {
        base_addr: 0,
        size: Size::S1M,
        subregions: Subregions::ALL,
        executable: true,
        // We need RW access, NVMC driver may update flash by writing directly
        // to memory.
        permissions: FullAccessPermissions::PrivilegedReadWriteUnprivilegedNoAccess,
        attributes: MemoryAttributes::Normal {
            shareable: true,
            cache_policy: CachePolicy::NonCacheable,
        },
    });
    // Part of FICR - allow access to device ID fields
    regions.push(Region {
        base_addr: 0x10000060,
        size: Size::S32B,
        subregions: Subregions::ALL,
        executable: false,
        permissions: FullAccessPermissions::PrivilegedReadOnlyUnprivilegedNoAccess,
        attributes: MemoryAttributes::Device { shareable: true },
    });
    // RAM region
    regions.push(Region {
        base_addr: 0x20000000,
        size: Size::S256K,
        subregions: Subregions::ALL,
        executable: false,
        permissions: FullAccessPermissions::PrivilegedReadWriteUnprivilegedNoAccess,
        attributes: MemoryAttributes::Normal {
            shareable: true,
            cache_policy: CachePolicy::NonCacheable,
        },
    });
    // AHB/APB peripherals region, covers entire 512 MiB region.
    regions.push(Region {
        base_addr: 0x40000000,
        size: Size::S512M,
        subregions: Subregions::ALL,
        executable: false,
        permissions: FullAccessPermissions::PrivilegedReadWriteUnprivilegedNoAccess,
        attributes: MemoryAttributes::Device { shareable: true },
    });
    // Private peripheral bus
    regions.push(Region {
        base_addr: 0xE0000000,
        size: Size::S512M,
        subregions: Subregions::ALL,
        executable: false,
        permissions: FullAccessPermissions::PrivilegedReadWriteUnprivilegedNoAccess,
        attributes: MemoryAttributes::Device { shareable: true },
    });
    // Protect 1 MiB region before stack to detect stack overflows.
    regions.push(Region {
        base_addr: 0x1FF00000,
        size: Size::S1M,
        subregions: Subregions::ALL,
        executable: false,
        permissions: FullAccessPermissions::PrivilegedNoAccessUnprivilegedNoAccess,
        attributes: MemoryAttributes::Normal {
            shareable: true,
            cache_policy: CachePolicy::NonCacheable,
        },
    });

    info!("Configuring MPU");
    let mut mpu = cortex_mpu::cortex_m4::Mpu::new(MaybeUninit::uninit().assume_init());
    mpu.configure(&regions);
}
