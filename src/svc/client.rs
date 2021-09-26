// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(unix), allow(unused_imports))]

use clap::App;
use signer::{signer_client::SignerClient, GenerateKeysRequest};

pub mod signer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // define the command line parameters to call the bls12381svc
    let matches = App::new("bls12381cli")
        .version("v0.1.0")
        .author("Loki <david@dusk.network>")
        .about("Generate keys, sign, aggregate and verify messages using BLS12-381 elliptic curves")
        .subcommand(App::new("generatekeys")
            .about("generate a secret and public key pair"))
        .subcommand(App::new("sign")
            .about("sign a message with a given key pair"))
        .subcommand(App::new("verify")
            .about("Verify a signature against message and public key"))
        .subcommand(App::new("createapk")
            .about("Convert a public key into an aggregated public key"))
        .subcommand(App::new("aggregatepk")
            .about("add more public keys ot an aggregated public key"))
        .subcommand(App::new("aggregatesig")
            .about("aggregate multiple signatures into one signature"))
        .get_matches();
    // creating a channel ie connection to server
    let channel =
        tonic::transport::Channel::from_static("http://127.0.0.1:9156")
            .connect()
            .await?;
    let mut client = SignerClient::new(channel);

    Ok(())
}
