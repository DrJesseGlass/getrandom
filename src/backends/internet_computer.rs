//! Backend for Internet Computer (IC) WASM canisters
//!
//! This backend uses the IC system API's raw_rand function to generate
//! cryptographically secure random bytes.

use crate::Error;
use core::mem::MaybeUninit;

// IC system API for randomness
// See: https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-random
#[link(wasm_import_module = "ic0")]
extern "C" {
    fn raw_rand(dst: *mut u8, len: u32);
}

pub fn fill_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    let len = dest.len();
    if len == 0 {
        return Ok(());
    }

    // SAFETY:
    // - IC's raw_rand will write exactly `len` bytes to `dst`
    // - The pointer is valid for writes of `len` bytes
    // - raw_rand initializes all bytes in the buffer
    unsafe {
        let ptr = dest.as_mut_ptr().cast::<u8>();
        raw_rand(ptr, len as u32);
    }

    Ok(())
}

pub fn inner_u32() -> Result<u32, Error> {
    let mut buf = [MaybeUninit::<u8>::uninit(); 4];
    fill_inner(&mut buf)?;

    // SAFETY: fill_inner succeeded, so buf is fully initialized
    let buf = unsafe {
        [
            buf[0].assume_init(),
            buf[1].assume_init(),
            buf[2].assume_init(),
            buf[3].assume_init(),
        ]
    };

    Ok(u32::from_ne_bytes(buf))
}

pub fn inner_u64() -> Result<u64, Error> {
    let mut buf = [MaybeUninit::<u8>::uninit(); 8];
    fill_inner(&mut buf)?;

    // SAFETY: fill_inner succeeded, so buf is fully initialized
    let buf = unsafe {
        [
            buf[0].assume_init(),
            buf[1].assume_init(),
            buf[2].assume_init(),
            buf[3].assume_init(),
            buf[4].assume_init(),
            buf[5].assume_init(),
            buf[6].assume_init(),
            buf[7].assume_init(),
        ]
    };

    Ok(u64::from_ne_bytes(buf))
}