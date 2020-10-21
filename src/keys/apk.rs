// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{h1, Error, PublicKey, Signature};
use dusk_bls12_381::G2Projective;

/// Aggregated form of a BLS public key.
/// The public keys are aggregated in a rogue-key attack
/// resistant manner, by using the hash function defined
/// in the modified version of BLS.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct APK {
    pk: PublicKey,
}

impl APK {
    /// Create a new [`APK`] from a [`PublicKey`].
    pub fn new(pk: &PublicKey) -> Self {
        let t = h1(pk);
        let gx = pk.gx * t;
        Self {
            pk: PublicKey { gx: gx.into() },
        }
    }

    /// Aggregate a set of [`PublicKey`] into the [`APK`].
    pub fn add(&mut self, pks: &[PublicKey]) {
        pks.iter().for_each(|pk| {
            self.pk.gx = (self.pk.gx + G2Projective::from(pk.pk_t())).into();
        });
    }

    /// Verify a [`Signature`].
    /// Wrapper function for PublicKey.verify.
    /// Currently, this function only supports batched signature verification
    /// for the same message. Distinct messages are not supported.
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.pk.verify(sig, msg)
    }
}
