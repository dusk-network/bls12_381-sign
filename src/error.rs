// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use thiserror::Error;

#[derive(Error, Debug)]
/// Standard error for the interface
pub enum Error {
    /// Cryptographic invalidity
    #[error("Signature verification failed")]
    InvalidSignature,
}
