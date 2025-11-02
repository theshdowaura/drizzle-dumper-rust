#[cfg(all(target_arch = "aarch64", target_os = "android"))]
use core::arch::asm;
#[cfg(all(target_arch = "aarch64", target_os = "android"))]
use core::ffi::c_void;

#[cfg(all(target_arch = "aarch64", target_os = "android"))]
const CACHE_LINE_SIZE: usize = 64;

/// Provide `__clear_cache` for Android/aarch64 targets where the NDK
/// toolchain does not ship the symbol. Frida's native dependencies
/// rely on it to invalidate instruction caches after writing code.
#[cfg(all(target_arch = "aarch64", target_os = "android"))]
#[no_mangle]
pub unsafe extern "C" fn __clear_cache(start: *mut c_void, end: *mut c_void) {
    if start.is_null() || end.is_null() {
        return;
    }

    let mut ptr = (start as usize) & !(CACHE_LINE_SIZE - 1);
    let end = end as usize;
    if ptr >= end {
        return;
    }

    // Clean data cache for the written region.
    while ptr < end {
        asm!("dc cvau, {addr}", addr = in(reg) ptr, options(nostack, preserves_flags));
        ptr += CACHE_LINE_SIZE;
    }
    asm!("dsb ish", options(nostack, preserves_flags));

    // Invalidate instruction cache for the same region.
    let mut ptr = (start as usize) & !(CACHE_LINE_SIZE - 1);
    while ptr < end {
        asm!("ic ivau, {addr}", addr = in(reg) ptr, options(nostack, preserves_flags));
        ptr += CACHE_LINE_SIZE;
    }
    asm!("dsb ish", options(nostack, preserves_flags));
    asm!("isb", options(nostack, preserves_flags));
}
