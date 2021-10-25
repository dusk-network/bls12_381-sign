// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(feature = "std"), no_std, feature(lang_items))]

//! Implementation of BLS signatures on the BLS12-381 curve.
//! Reference paper: https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html

mod error;
mod ffi;
mod keys;
mod signature;

#[cfg(feature = "std")]
mod hash;

pub use error::Error;
pub use keys::{apk::APK, public::PublicKey, secret::SecretKey};
pub use signature::Signature;

#[cfg(not(any(test, feature = "std")))]
mod panic_handling {
    use core::panic::PanicInfo;

    #[panic_handler]
    fn panic(_: &PanicInfo) -> ! {
        loop {}
    }

    #[lang = "eh_personality"]
    extern "C" fn eh_personality() {}
}
