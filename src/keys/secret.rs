// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{h0, h1, Error, PublicKey, Signature};
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use rand_core::{CryptoRng, RngCore};

/// A BLS secret key, holding a BLS12-381 scalar inside.
/// Can be used for signing messages.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct SecretKey(pub(crate) BlsScalar);

impl SecretKey {
    /// Generates a new random [`SecretKey`].
    pub fn new<T>(rand: &mut T) -> Self
    where
        T: RngCore + CryptoRng,
    {
        Self(BlsScalar::random(rand))
    }

    /// Sign a message, producing a [`Signature`].
    /// The signature produced is vulnerable to a rogue-key attack.
    pub fn sign_vulnerable(&self, msg: &[u8]) -> Signature {
        // Hash message
        let h = h0(msg);

        // Multiply point by sk
        let e = h * self.0;
        Signature(e.into())
    }

    /// Sign a message in a rogue-key attack resistant way.
    pub fn sign(&self, pk: &PublicKey, msg: &[u8]) -> Signature {
        let mut sig = self.sign_vulnerable(msg);

        // Turn signature into its modified construction,
        // which provides protection against rogue-key attacks.
        let t = h1(pk);
        sig.0 = (sig.0 * t).into();
        sig
    }

    /// Return the byte representation of the [`SecretKey`]
    pub fn to_bytes(&self) -> [u8; SecretKey::serialized_size()] {
        self.0.to_bytes()
    }

    /// Attempt to create a [`SecretKey`] from a BLS scalar byte representation.
    pub fn from_bytes(
        bytes: &[u8; SecretKey::serialized_size()],
    ) -> Result<Self, Error> {
        Ok(Self(
            BlsScalar::from_bytes(bytes).or(Err(Error::InvalidBytes))?,
        ))
    }

    /// Return the amount of bytes needed to serialize a [`SecretKey`].
    pub const fn serialized_size() -> usize {
        32
    }
}
