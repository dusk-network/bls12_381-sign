// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{h0, h1, Error, SecretKey, Signature};
use dusk_bls12_381::G2Affine;

/// A BLS public key, holding a BLS12-381 G2 element inside.
/// The G2 element is constructed by multiplying a [`SecretKey`] `x`
/// by `g2` (the base point of the G2 group).
/// Can be used for signature verification.
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicKey {
    pub(crate) gx: G2Affine,
}

impl PublicKey {
    /// Generates a new [`PublicKey`] from a [`SecretKey`].
    /// pk = g_2 * x
    pub fn new(sk: &SecretKey) -> Self {
        let g_2 = G2Affine::generator();
        let gx = g_2 * sk.x;

        Self { gx: gx.into() }
    }

    /// Verify a [`Signature`] by comparing the results of the two pairing
    /// operations: e(sig, g_2) == e(Hₒ(m), pk).
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> Result<(), Error> {
        let h0m = h0(msg);
        let p1 = dusk_bls12_381::pairing(&sig.e, &G2Affine::generator());
        let p2 = dusk_bls12_381::pairing(&h0m, &self.gx);

        match p1.eq(&p2) {
            true => Ok(()),
            false => Err(Error::InvalidSignature),
        }
    }

    /// Return gx * t, where t is H_(gx).
    pub fn pk_t(&self) -> G2Affine {
        let t = h1(self);
        let gx = self.gx * t;
        gx.into()
    }

    /// Return the compressed byte representation of the [`PublicKey`].
    pub fn to_bytes(&self) -> [u8; 96] {
        self.gx.to_compressed()
    }
}
