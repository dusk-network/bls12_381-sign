// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(feature = "std"), no_std)]

//! Implementation of BLS signatures on the BLS12-381 curve.
//! Reference paper: https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html

mod error;
mod ffi;
#[cfg(feature = "std")]
mod hash;
mod keys;
mod signature;
mod tests;

pub use error::Error;
#[cfg(feature = "std")]
pub use hash::{h0, h1};
pub use keys::{apk::APK, public::PublicKey, secret::SecretKey};
pub use signature::Signature;

// todo: this is commented out because it appears to already be defined in another place and causes
//  the no-std tests to fail, which is just `cargo check --no-default-features` and `std` is a
//  default feature
//
// #[cfg(not(feature = "std"))]
// use core::panic::PanicInfo;
//
// /// This function is called on panic.
// #[cfg(not(feature = "std"))]
// #[panic_handler]
// fn panic(_info: &PanicInfo) -> ! {
//     loop {}
// }
