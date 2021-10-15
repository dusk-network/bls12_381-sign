// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(unix), allow(unused_imports))]

#[cfg(feature = "std")]
#[cfg(unix)]
mod unix;

#[cfg(feature = "std")]
tonic::include_proto!("signer");

#[cfg(feature = "std")]
use {
    aggregate_response::Agg::Code,
    create_apk_response::Apk::Apk,
    dusk_bls12_381_sign::{PublicKey, SecretKey, Signature, APK},
    futures::TryFutureExt,
    sign_response::Sig::Signature as ResponseSignature,
    signer_server::{Signer, SignerServer},
    // std::path::Path,
    std::process::exit,
    tokio::net::UnixListener,
    tonic::{transport::Server, Request, Response, Status},
    verify_response::Ver::Valid,
    // log,
};

#[cfg(feature = "std")]
#[derive(Default)]
pub struct MySign {}

/// The following macros are written to minimize memory handling with [core::mem::transmute], and by
/// early return on error from the calling function to reduce repeated match branches that are
/// basically all the same
#[cfg(feature = "std")]
#[macro_export]
macro_rules! slice_as_array_transmute {
    ($slice:expr) => {
        ::core::mem::transmute($slice)
    };
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! slice_as {
    ($slice:expr, $wrapper:ty, $note:literal) => {{
        unsafe fn this_transmute(
            xs: &[u8],
        ) -> &[u8; <$wrapper>::serialized_size()] {
            slice_as_array_transmute!(xs.as_ptr())
        }

        let s: &[u8] = $slice;
        if s.len() != <$wrapper>::serialized_size() {
            return Err(Status::invalid_argument(format!(
                "{}: provided vector is wrong length: {} should be {}",
                $note,
                s.len(),
                <$wrapper>::serialized_size(),
            )));
        } else {
            match <$wrapper>::from_bytes(unsafe { this_transmute(s) }) {
                Ok(v) => v,
                Err(_) => {
                    return Err(Status::invalid_argument(format!(
                        "unable to convert to type {}",
                        $note
                    )))
                }
            }
        }
    }};
}

#[cfg(feature = "std")]
#[tonic::async_trait]
impl Signer for MySign {
    /// BLS12-381 Signer service implementation

    /// Generate a new BLS12-381 key pair
    async fn generate_keys(
        &self,
        _request: Request<GenerateKeysRequest>,
    ) -> Result<Response<GenerateKeysResponse>, Status> {
        // get a new random secret key from system entropy
        let sk = SecretKey::new(&mut rand_core::OsRng);

        // construct the gRPC response from the key and return it
        Ok(Response::new(GenerateKeysResponse {
            secret_key: sk.to_bytes().to_vec(),
            public_key: PublicKey::from(&sk).to_bytes().to_vec(),
        }))
    }

    /// Sign a message using a provided BLS12-381 key pair
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let sk = slice_as!(req.secret_key.as_slice(), SecretKey, "SecretKey");
        let pk = slice_as!(req.public_key.as_slice(), PublicKey, "PublicKey");
        // sign the message
        let res = ResponseSignature(
            sk.sign(&pk, req.message.as_slice()).to_bytes().to_vec(),
        );

        // return the signature wrapped in the response type
        Ok(Response::new(SignResponse {
            sig: Option::Some(res),
        }))
    }

    /// Verify a BLS12-381 signature on a message with a given public key
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let apk = slice_as!(req.apk.as_slice(), APK, "APK");
        let sig = slice_as!(req.signature.as_slice(), Signature, "Signature");

        // verify the message matches the signature and the signature matches the
        // given public key
        let res = apk.verify(&sig, &req.message);

        // return whether the verification returned no error
        Ok(Response::new(VerifyResponse {
            ver: Some(Valid(!res.is_err())),
        }))
    }

    /// Create an aggregated public key from a public key
    async fn create_apk(
        &self,
        request: Request<CreateApkRequest>,
    ) -> Result<Response<CreateApkResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let apk = slice_as!(req.public_key.as_slice(), PublicKey, "PublicKey");
        let apk = APK::from(&apk);
        Ok(Response::new(CreateApkResponse {
            apk: Some(Apk(apk.to_bytes().to_vec())),
        }))
    }

    /// Aggregate a collection of public keys to an aggregated public key
    async fn aggregate_pk(
        &self,
        request: Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        // get the apk first
        let apk = slice_as!(&req.apk, PublicKey, "PublicKey");
        let mut apk = APK::from_bytes(&apk.to_bytes()).unwrap();
        // collect the list of public keys into a vector
        let mut pks = Vec::with_capacity(req.keys.len());
        for elem in &req.keys {
            pks.push(slice_as!(&elem, PublicKey, "PublicKey"));
        }
        // aggregate the keys
        apk.aggregate(&pks);
        let bytes = apk.to_bytes();
        // convert public key to aggregated public key and return it
        Ok(Response::new(AggregateResponse {
            agg: Some(Code(bytes.into())),
        }))
    }

    /// Aggregate a collection of signatures into an aggregated signature
    async fn aggregate_sig(
        &self,
        request: Request<AggregateSigRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let sig = slice_as!(req.signature.as_slice(), Signature, "Signature");

        // convert the raw bytes from the message to a collection of signatures
        let mut sigs: Vec<Signature> = Vec::with_capacity(req.signatures.len());
        // collect the list of public keys into a vector
        for elem in &req.signatures {
            sigs.push(slice_as!(&elem, Signature, "Signature"));
        }

        // aggregate the signatures
        let sig = sig.aggregate(&sigs);

        let bytes = sig.to_bytes().into();

        // convert aggregate signature to bytes and return
        Ok(Response::new(AggregateResponse {
            agg: Some(Code(bytes)),
        }))
    }
}

#[cfg(feature = "std")]
extern crate ctrlc;

/// Default UDS path that Rusk GRPC-server will connect to.
pub const SOCKET_PATH: &str = "/tmp/bls12381svc.sock";

#[cfg(feature = "std")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let path = "127.0.0.1:9476".parse().unwrap();
    let path = SOCKET_PATH;
    let uds = UnixListener::bind(path)?;

    // adding our service to our server.
    let signeur = MySign::default();

    let signer = SignerServer::new(signeur);

    let incoming = {
        async_stream::stream! {
            while let item = uds.accept().map_ok(|(st, _)| unix::UnixStream(st)).await {
                yield item;
            }
        }
    };

    ctrlc::set_handler(move || {
        exit(0);
    })?;
    Server::builder()
        // .accept_http1(false)
        .add_service(signer)
        // .serve(path)
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    panic!("Unix Domain Sockets can only be used on unix systems!");
}

#[cfg(not(feature = "std"))]
fn main() {
    panic!("std feature required");
}
