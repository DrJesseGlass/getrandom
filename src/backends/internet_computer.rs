//! Backend for Internet Computer (IC) WASM canisters
//!
//! Uses deterministic values since IC's raw_rand is async-only
//! and cannot be called synchronously from getrandom.
//!
//! This is safe for inference workloads that don't require cryptographic randomness.

use crate::Error;
use core::mem::MaybeUninit;

pub fn fill_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    let len = dest.len();
    if len == 0 {
        return Ok(());
    }

    // Deterministic fill pattern - repeatable but sufficient for non-crypto use
    // Uses a simple PRNG-like pattern for better distribution
    for (i, byte) in dest.iter_mut().enumerate() {
        unsafe {
            // Simple mixing function for better value distribution
            let val = (i.wrapping_mul(73).wrapping_add(197)) as u8;
            byte.write(val);
        }
    }

    Ok(())
}

pub fn inner_u32() -> Result<u32, Error> {
    let mut buf = [MaybeUninit::<u8>::uninit(); 4];
    fill_inner(&mut buf)?;

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