// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Defines the hash functions needed for the BLS signature scheme.

use crate::PublicKey;
use blake2::{Blake2b, Digest};
use dusk_bls12_381::{G1Affine, Scalar as BlsScalar};
use std::convert::TryInto;

/// h0 is the hash-to-curve-point function.
/// Hₒ : M -> Gₒ
pub fn h0(msg: &[u8]) -> G1Affine {
    let hash = Blake2b::digest(msg);
    let scalar = BlsScalar::from_bytes_wide(
        hash.as_slice().try_into().expect("Wrong length"),
    );

    // Now multiply this message by the G1 base point,
    // to generate a G1Affine.
    let h = G1Affine::generator() * scalar;
    h.into()
}

/// h1 is the hashing function used in the modified BLS
/// multi-signature construction.
/// H₁ : G₂ -> R
pub fn h1(pk: &PublicKey) -> BlsScalar {
    let hash = Blake2b::digest(&pk.to_bytes());
    BlsScalar::from_bytes_wide(
        hash.as_slice().try_into().expect("Wrong length"),
    )
}
