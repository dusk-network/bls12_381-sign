// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Defines the hash functions needed for the BLS signature scheme.

use crate::PublicKey;
use blake2::{Blake2s, Digest};
use dusk_bls12_381::{G1Affine, Scalar as BlsScalar};

/// h0 is the hash-to-curve-point function.
/// Hₒ : M -> Gₒ
pub fn h0(msg: &[u8]) -> G1Affine {
    // Hash the given message.
    let mut hasher = Blake2s::new();
    hasher.update(msg);
    let res = hasher.finalize();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&res[..]);

    // Ensure that the value is lower than the BLS12-381
    // modulus, by cutting the value to be max 2^254.
    // This will create a canonical array of bytes which
    // we can convert into a BLS scalar without issues.
    arr[31] &= 0b0011_1111;

    // Turn the hash into a BLS scalar.
    // NOTE: the unwrap here is done for a reason: it is
    // mimicking the code found here:
    // https://github.com/dusk-network/bls12_381/blob/master/src/scalar.rs#L473
    //
    // We should be able to unwrap safely since we cut the
    // value to be < 2^254.
    let scalar = BlsScalar::from_bytes(&arr).unwrap();

    // Now multiply this message by the G1 base point,
    // to generate a G1Affine.
    let h = G1Affine::generator() * scalar;
    h.into()
}

/// h1 is the hashing function used in the modified BLS
/// multi-signature construction.
/// H₁: G₂ -> R
pub fn h1(pk: &PublicKey) -> BlsScalar {
    let mut hasher = Blake2s::new();
    hasher.update(pk.to_bytes());
    let res = hasher.finalize();

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&res[..]);

    // NOTE: see above explanation
    arr[31] &= 0b0011_1111;
    let scalar = BlsScalar::from_bytes(&arr).unwrap();
    scalar
}
