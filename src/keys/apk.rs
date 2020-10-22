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
pub struct APK(PublicKey);

impl From<&PublicKey> for APK {
    fn from(pk: &PublicKey) -> Self {
        let t = h1(pk);
        let gx = pk.0 * t;
        Self(PublicKey(gx.into()))
    }
}

impl APK {
    /// Aggregate a set of [`PublicKey`] into the [`APK`].
    pub fn aggregate(&mut self, pks: &[PublicKey]) {
        (self.0).0 = pks.iter().fold((self.0).0, |acc, pk| {
            (acc + G2Projective::from(pk.pk_t())).into()
        });
    }

    /// Verify a [`Signature`].
    /// Wrapper function for PublicKey.verify.
    /// Currently, this function only supports batched signature verification
    /// for the same message. Distinct messages are not supported.
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.0.verify(sig, msg)
    }
}
