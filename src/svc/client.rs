// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(unix), allow(unused_imports))]

tonic::include_proto!("signer");

use clap::App;
use signer_client::SignerClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // define the command line parameters to call the bls12381svc
    let matches = App::new("bls12381cli")
        .version("v0.1.0")
        .author("Loki <david@dusk.network>")
        .about("Generate keys, sign, aggregate and verify messages using BLS12-381 elliptic curves")
        .subcommand(App::new("gen")
            .about("Generate a new BLS12-381 key pair"))
        .subcommand(App::new("sign")
            .about("Sign a message with a given key pair")
            .arg("<secretkey> 'Secret key'")
            .arg("<publickey> 'Public key'")
            .arg("<message> 'Message to be signed'")
        )
        .subcommand(App::new("verify")
            .about("Verify a signature against message and public key")
            .arg("<apk> '(Aggregated) Public key'")
            .arg("<signature> 'Signature'")
            .arg("<message> 'Message bearing signature'")
        )
        .subcommand(App::new("createapk")
            .about("Convert a public key into an aggregated public key")
            .arg("<publickey> 'Public key'")
       )
        .subcommand(App::new("aggregatepk")
            .about("Add more public keys to an aggregated public key")
            .arg("<secretkey> 'Aggregated public key'")
            .arg("<publickey>... 'Public Key'")
       )
        .subcommand(App::new("aggregatesig")
            .about("Aggregate multiple signatures into one signature")
            .arg("<signature> 'signature to aggregate into'")
            .arg("<signatures>... 'signatures to be merged into the first'")
      )
        .get_matches();
    // // creating a channel ie connection to server
    // let channel =
    //     tonic::transport::Channel::from_static("http://127.0.0.1:9156")
    //         .connect()
    //         .await?;
    // let mut client = SignerClient::new(channel);
    println!("{:?}", matches);
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
