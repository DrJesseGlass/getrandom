//! Backend for Internet Computer (IC) WASM canisters
//!
//! # ⚠️ WARNING: NOT CRYPTOGRAPHICALLY SECURE
//!
//! This backend provides **deterministic pseudo-random bytes** seeded from
//! canister execution state. It exists solely to satisfy dependencies that
//! require `getrandom` for non-security purposes (e.g., ML inference,
//! hash table initialization).
//!
//! **DO NOT USE** for key generation, nonces, tokens, or any security-sensitive purpose.
//!
//! IC's `raw_rand()` is async-only and cannot be called from synchronous `getrandom`.

use crate::Error;
use core::mem::MaybeUninit;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use ic_cdk::api::{instruction_counter, time};

#[inline]
fn splitmix64_next(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

pub fn fill_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    let len = dest.len();
    if len == 0 {
        return Ok(());
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    let mut state = time() ^ instruction_counter() ^ (len as u64).wrapping_mul(0x9E3779B97F4A7C15);

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    let mut state = (len as u64).wrapping_mul(0x9E3779B97F4A7C15);

    let mut i = 0;
    while i < len {
        let word = splitmix64_next(&mut state).to_le_bytes();
        let n = core::cmp::min(8, len - i);
        for j in 0..n {
            dest[i + j].write(word[j]);
        }
        i += n;
    }
    Ok(())
}

pub fn inner_u32() -> Result<u32, Error> {
    let mut buf = [MaybeUninit::<u8>::uninit(); 4];
    fill_inner(&mut buf)?;
    Ok(u32::from_ne_bytes(core::array::from_fn(|i| unsafe {
        buf[i].assume_init()
    })))
}

pub fn inner_u64() -> Result<u64, Error> {
    let mut buf = [MaybeUninit::<u8>::uninit(); 8];
    fill_inner(&mut buf)?;
    Ok(u64::from_ne_bytes(core::array::from_fn(|i| unsafe {
        buf[i].assume_init()
    })))
}
