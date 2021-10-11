// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(unix), allow(unused_imports))]

#[cfg(feature = "std")]
tonic::include_proto!("signer");

#[cfg(feature = "std")]
use {
    clap::App,
    signer_client::SignerClient,
    std::convert::TryFrom,
    tokio::net::UnixStream,
    tonic::transport::{Endpoint, Uri},
    tower::service_fn,
};

#[cfg(feature = "std")]
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
    println!("{:?}", matches);

    // create a channel to connect to the socket of the server
    let path: &str = "/tmp/bls12381svc.sock";
    let channel = Endpoint::try_from("http://[::]:50051")
        .expect("Serde error on addr reading")
        .connect_with_connector(service_fn(move |_: Uri| {
            UnixStream::connect(path)
        }))
        .await
        .expect("Error generating a Channel");

    let mut client = SignerClient::new(channel);
    // here we are just making a token request and not formatting the output correctly
    let request = tonic::Request::new(GenerateKeysRequest {});
    let response = client.generate_keys(request).await?;
    println!("Secret key {:?}", response.get_ref().secret_key);
    println!("Public key {:?}", response.get_ref().public_key);
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() {
    panic!("IPC service requires std feature")
}
