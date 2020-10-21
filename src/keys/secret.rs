// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{h0, h1, PublicKey, Signature};
use dusk_bls12_381::Scalar as BlsScalar;
use rand::{CryptoRng, Rng};

/// A BLS secret key, holding a BLS12-381 scalar inside.
/// Can be used for signing messages.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct SecretKey {
    pub(crate) x: BlsScalar,
}

impl SecretKey {
    /// Generates a new random [`SecretKey`].
    pub fn new<T>(rand: &mut T) -> Self
    where
        T: Rng + CryptoRng,
    {
        Self {
            x: BlsScalar::random(rand),
        }
    }

    /// Sign a message, producing a [`Signature`].
    /// The signature produced is not resistant to a rogue-key attack.
    pub fn unsafe_sign(&self, msg: &[u8]) -> Signature {
        // Hash message
        let h = h0(msg);

        // Multiply point by sk
        let e = h * self.x;
        Signature { e: e.into() }
    }

    /// Sign a message in a rogue-key attack resistant way.
    pub fn sign(&self, pk: &PublicKey, msg: &[u8]) -> Signature {
        let mut sig = self.unsafe_sign(msg);

        // Turn signature into its modified construction.
        let t = h1(pk);
        sig.e = (sig.e * t).into();
        sig
    }
}
