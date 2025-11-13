//! Backend for Internet Computer (IC) WASM canisters
//!
//! Uses deterministic values since IC's raw_rand is async-only
//! and cannot be called synchronously from getrandom.
//!
//! This is safe for inference workloads that don't require cryptographic randomness.

use crate::Error;
use core::mem::MaybeUninit;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use ic_cdk::api::time;

// SplitMix64: tiny, fast, good distribution for non-crypto use
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

    // Consensus timestamp: deterministic across replicas in an UPDATE call.
    // (In a QUERY it is *not* consensus-certified.)
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    let mut state = (time() as u64) ^ ((len as u64).wrapping_mul(0x9E3779B97F4A7C15));

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    let mut state = (len as u64).wrapping_mul(0x9E3779B97F4A7C15); // fallback seed

    let mut i = 0;
    while i < len {
        let word = splitmix64_next(&mut state).to_le_bytes();
        let n = core::cmp::min(8, len - i);
        for j in 0..n {
            unsafe { dest[i + j].write(word[j]); }
        }
        i += n;
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