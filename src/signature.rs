// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::{G1Affine, G1Projective};

/// A BLS signature.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct Signature {
    pub(crate) e: G1Affine,
}

impl Signature {
    /// Aggregate a set of signatures by simply adding up the points.
    pub fn aggregate(&self, sigs: &[Signature]) -> Self {
        Self {
            e: sigs.iter().fold(self.e, |acc, sig| {
                (acc + G1Projective::from(sig.e)).into()
            }),
        }
    }
}
