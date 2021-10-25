// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "std")]
use crate::{h1, Signature};
use crate::{Error, PublicKey};
#[cfg(feature = "canon")]
// use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
#[cfg(feature = "std")]
use dusk_bls12_381::G2Projective;

/// Aggregated form of a BLS public key.
/// The public keys are aggregated in a rogue-key attack
/// resistant manner, by using the hash function defined
/// in the modified version of BLS.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct APK(PublicKey);

#[cfg(feature = "std")]
impl From<&PublicKey> for APK {
    fn from(pk: &PublicKey) -> Self {
        let t = h1(pk);
        let gx = pk.0 * t;
        Self(PublicKey(gx.into()))
    }
}

impl APK {
    /// Aggregate a set of [`PublicKey`] into the [`APK`].
    #[cfg(feature = "std")]
    pub fn aggregate(&mut self, pks: &[PublicKey]) {
        (self.0).0 = pks.iter().fold((self.0).0, |acc, pk| {
            (acc + G2Projective::from(pk.pk_t())).into()
        });
    }

    /// Verify a [`Signature`].
    /// Wrapper function for PublicKey.verify.
    /// Currently, this function only supports batched signature verification
    /// for the same message. Distinct messages are not supported.
    #[cfg(feature = "std")]
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.0.verify(sig, msg)
    }

    /// Return the compressed byte representation of the [`APK`].
    pub fn to_bytes(&self) -> [u8; APK::serialized_size()] {
        self.0.to_bytes()
    }

    /// Attempt to create a [`APK`] from a G2Affine byte representation.
    pub fn from_bytes(
        bytes: &[u8; APK::serialized_size()],
    ) -> Result<Self, Error> {
        Ok(APK(PublicKey::from_bytes(bytes)?))
    }

    /// Return the amount of bytes needed to serialize a [`APK`].
    pub const fn serialized_size() -> usize {
        96
    }
}
