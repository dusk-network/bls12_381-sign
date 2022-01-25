// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{hash::h1, Signature};
use crate::{Error, PublicKey, SecretKey};

use dusk_bytes::Serializable;

#[cfg(feature = "canon")]
use canonical_derive::Canon;

/// Aggregated form of a BLS public key.
/// The public keys are aggregated in a rogue-key attack
/// resistant manner, by using the hash function defined
/// in the modified version of BLS.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct APK(PublicKey);

impl Serializable<96> for APK {
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Error> {
        Ok(APK(PublicKey::from_bytes(bytes)?))
    }
}

impl From<&PublicKey> for APK {
    fn from(pk: &PublicKey) -> Self {
        let t = h1(pk);
        let gx = pk.0 * t;
        Self(PublicKey(gx.into()))
    }
}

impl From<&SecretKey> for APK {
    fn from(sk: &SecretKey) -> Self {
        let pk = PublicKey::from(sk);

        Self::from(&pk)
    }
}

impl APK {
    /// Aggregate a set of [`PublicKey`] into the [`APK`].
    pub fn aggregate(&mut self, pks: &[PublicKey]) {
        (self.0).0 = pks.iter().fold((self.0).0, |acc, pk| {
            (acc + dusk_bls12_381::G2Projective::from(pk.pk_t())).into()
        });
    }

    /// Verify a [`Signature`].
    /// Wrapper function for PublicKey.verify.
    /// Currently, this function only supports batched signature verification
    /// for the same message. Distinct messages are not supported.
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> Result<(), Error> {
        self.0.verify(sig, msg)
    }

    /// Raw bytes representation
    ///
    /// The intended usage of this function is for trusted sets of data where
    /// performance is critical.
    ///
    /// For secure serialization, check `to_bytes`
    pub fn to_raw_bytes(&self) -> [u8; dusk_bls12_381::G2Affine::RAW_SIZE] {
        self.0.to_raw_bytes()
    }

    /// Create a `APK` from a set of bytes created by `APK::to_raw_bytes`.
    ///
    /// # Safety
    ///
    /// No check is performed and no constant time is granted. The expected
    /// usage of this function is for trusted bytes where performance is
    /// critical.
    ///
    /// For secure serialization, check `from_bytes`
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        APK(PublicKey::from_slice_unchecked(bytes))
    }
}
