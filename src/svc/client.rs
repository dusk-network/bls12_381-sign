// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(unix), allow(unused_imports))]

use signer::{signer_client::SignerClient, GenerateKeysRequest};

pub mod signer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // creating a channel ie connection to server
    let channel =
        tonic::transport::Channel::from_static("http://127.0.0.1:9156")
            .connect()
            .await?;
    let mut client = SignerClient::new(channel);
    let request = tonic::Request::new(GenerateKeysRequest {});
    let response = client.generate_keys(request).await?;
    println!("Secret key {:?}", response.get_ref().secret_key);
    println!("Public key {:?}", response.get_ref().public_key);
    Ok(())
}
