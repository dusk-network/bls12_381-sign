// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::Error;
use dusk_bls12_381::{G1Affine, G1Projective};

/// A BLS signature.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct Signature(pub(crate) G1Affine);

impl Signature {
    /// Aggregate a set of signatures by simply adding up the points.
    pub fn aggregate(&self, sigs: &[Signature]) -> Self {
        Self(
            sigs.iter().fold(self.0, |acc, sig| {
                (acc + G1Projective::from(sig.0)).into()
            }),
        )
    }

    /// Return the compressed byte representation of the [`Signature`].
    pub fn to_bytes(&self) -> [u8; Signature::serialized_size()] {
        self.0.to_compressed()
    }

    /// Attempt to create a [`Signature`] from a G1Affine compressed
    /// byte representation.
    pub fn from_bytes(
        bytes: &[u8; Signature::serialized_size()],
    ) -> Result<Self, Error> {
        let s = Option::from(G1Affine::from_compressed(bytes))
            .ok_or(Error::InvalidBytes)?;
        Ok(Self(s))
    }

    /// Return the amount of bytes needed to serialize a [`Signature`].
    pub const fn serialized_size() -> usize {
        48
    }
}
