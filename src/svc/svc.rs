// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![feature(test)]
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
#[macro_export]
macro_rules! slice_as_fixed {
    ($slice:expr, $wrapper:ty, $note:literal, $length:expr) => {{
        unsafe fn this_transmute(
            xs: &[u8],
        ) -> &[u8; <$length>] {
            slice_as_array_transmute!(xs.as_ptr())
        }

        let s: &[u8] = $slice;

            match <$wrapper>::from_bytes(unsafe { this_transmute(s) }) {
                Ok(v) => v,
                Err(_) => {
                    return Err(Status::invalid_argument(format!(
                        "unable to convert to type {}",
                        $note
                    )))
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
            public_key: PublicKey::from(&sk).to_raw_bytes().to_vec(),
        }))
    }

    /// Sign a message using a provided BLS12-381 key pair
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        self.sign_sync(&request)
    }

    /// Verify a BLS12-381 signature on a message with a given public key
    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        self.verify_sync(&request)
    }

    /// Create an aggregated public key from a public key
    async fn create_apk(
        &self,
        request: Request<CreateApkRequest>,
    ) -> Result<Response<CreateApkResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let pk = MySign::public_from_raw_unchecked(&req.public_key)?;
        let apk = APK::from(&pk);
        Ok(Response::new(CreateApkResponse {
            apk: Some(Apk(apk.to_raw_bytes().to_vec())),
        }))
    }

    /// Aggregate a collection of public keys to an aggregated public key
    async fn aggregate_pk(
        &self,
        request: Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        self.aggregate_pk_sync(&request)
    }

    /// Aggregate a collection of signatures into an aggregated signature
    async fn aggregate_sig(
        &self,
        request: Request<AggregateSigRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let sig = slice_as!(&req.signature, Signature, "Signature");

        // convert the raw bytes from the message to a collection of signatures
        let mut sigs: Vec<Signature> = Vec::with_capacity(req.signatures.len());
        // collect the list of public keys into a vector
        for elem in &req.signatures {
            sigs.push(slice_as!(elem, Signature, "Signature"));
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

impl MySign {
    fn slice_to_fixed<const N: usize>(s: &[u8]) -> Result<[u8; N], Status> {
        if s.len() != N {
            Err(Status::invalid_argument(format!(
                "invalid length {} - expected {}",
                s.len(),
                N
            )))
        } else {
            let mut a: [u8; N] = [0u8; N];
            a.copy_from_slice(s);
            Ok(a)
        }
    }

    fn signature_from_bytes(s: &[u8]) -> Result<Signature, Status> {
        let sig_bytes = MySign::slice_to_fixed(s)?;
        Signature::from_bytes(&sig_bytes)
            .map_err(|_| Status::invalid_argument("Invalid signature bytes"))
    }

    fn public_from_raw_unchecked(s: &[u8]) -> Result<PublicKey, Status> {
        let pk_bytes = MySign::slice_to_fixed(s)?;
        PublicKey::from_raw_bytes(&pk_bytes)
            .map_err(|_| Status::invalid_argument("Invalid public key"))
    }

    fn apk_from_raw_unchecked(s: &[u8]) -> Result<APK, Status> {
        let pk_bytes = MySign::slice_to_fixed(s)?;
        APK::from_raw_bytes(&pk_bytes).map_err(|_| {
            Status::invalid_argument("Invalid aggregated public key")
        })
    }

    fn sign_sync(
        &self,
        request: &Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let sk = slice_as!(req.secret_key.as_slice(), SecretKey, "SecretKey");
        let pk = MySign::public_from_raw_unchecked(&req.public_key)?;
        let res =
            ResponseSignature(sk.sign(&pk, &req.message).to_bytes().to_vec());
        // return the signature wrapped in the response type
        Ok(Response::new(SignResponse { sig: Some(res) }))
    }
    /// Verify a BLS12-381 signature on a message with a given public key
    fn verify_sync(
        &self,
        request: &Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let apk = MySign::apk_from_raw_unchecked(&req.apk)?;
        let sig = MySign::signature_from_bytes(&req.signature)?;

        // verify the message matches the signature and the signature matches the
        // given public key
        let res = apk.verify(&sig, &req.message);
        // return whether the verification returned no error
        Ok(Response::new(VerifyResponse {
            ver: Some(Valid(res.is_ok())),
        }))
    }
    fn aggregate_pk_sync(
        &self,
        request: &Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        // get the apk first
        let mut apk = MySign::apk_from_raw_unchecked(&req.apk)?;
        // collect the list of public keys into a vector
        let mut pks = Vec::with_capacity(req.keys.len());
        for elem in &req.keys {
            pks.push(MySign::public_from_raw_unchecked(elem)?);
        }
        // aggregate the keys
        apk.aggregate(&pks);
        // convert public key to aggregated public key and return it
        Ok(Response::new(AggregateResponse {
            agg: Some(Code(apk.to_raw_bytes().to_vec())),
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
            loop{
                let item = uds.accept().map_ok(|(st, _)| unix::UnixStream(st)).await;
                yield item;
            };
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

extern crate test;

#[cfg(test)]
mod benches_svc {
    use dusk_bls12_381_sign::{PublicKey, SecretKey};
    use rand::RngCore;
    use test::Bencher;

    use crate::*;

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let signer = MySign {};
        let sk = SecretKey::new(&mut rand::thread_rng());
        let req = Request::new(SignRequest {
            message: random_message().to_vec(),
            public_key: PublicKey::from(&sk).to_raw_bytes().to_vec(),
            secret_key: sk.to_bytes().to_vec(),
        });
        b.iter(|| signer.sign_sync(&req));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from(&sk);
        let msg = random_message().to_vec();
        let signer = MySign {};
        let req = Request::new(SignRequest {
            message: msg.to_vec(),
            public_key: pk.to_raw_bytes().to_vec(),
            secret_key: sk.to_bytes().to_vec(),
        });
        let signres = signer.sign_sync(&req).unwrap();
        let sig = signres.get_ref().sig.as_ref().unwrap();
        if let ResponseSignature(a) = sig {
            let ver = Request::new(VerifyRequest {
                apk: APK::from(&pk).to_raw_bytes().to_vec(),
                signature: a.to_vec(),
                message: msg.to_vec(),
            });
            b.iter(|| {
                let signer = MySign {};
                let mut res = signer.verify_sync(&ver).unwrap();
                let a = res.get_mut().ver.take();
                match a.unwrap() {
                    Valid(e) => {
                        assert!(e);
                    }
                    _ => {
                        assert!(false);
                    }
                }
            });
        } else {
            panic!("help")
        }
    }

    fn random_message() -> [u8; 100] {
        let mut msg = [0u8; 100];
        (&mut rand::thread_rng()).fill_bytes(&mut msg);
        msg
    }
}

#[cfg(test)]
mod tests_svc {
    use crate::*;
    use crate::{PublicKey, SecretKey, APK};
    use rand::RngCore;

    #[test]
    fn sign_verify() {
        let signer = MySign {};
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from(&sk);
        let msg = random_message().to_vec();
        let req = Request::new(SignRequest {
            message: msg.to_vec(),
            public_key: pk.to_raw_bytes().to_vec(),
            secret_key: sk.to_bytes().to_vec(),
        });
        let signres = signer.sign_sync(&req).unwrap();
        let sig = signres.get_ref().sig.as_ref().unwrap();

        if let ResponseSignature(a) = sig {
            let ver = Request::new(VerifyRequest {
                apk: APK::from(&pk).to_raw_bytes().to_vec(),
                signature: a.to_vec(),
                message: msg.to_vec(),
            });

            let sig = MySign::slice_to_fixed(&a).unwrap();
            let sig = Signature::from_bytes(&sig).unwrap();
            // Verification with the standard pk should fail.
            assert!(pk.verify(&sig, &msg).is_err());

            // Verification with the aggregated version should work.
            let apk = APK::from(&pk);
            assert!(apk.verify(&sig, &msg).is_ok());

            let signer = MySign {};
            let mut res = signer.verify_sync(&ver).unwrap();
            let a = res.get_mut().ver.take();
            match a.unwrap() {
                Valid(e) => {
                    assert!(e);
                }
                _ => {
                    assert!(false);
                }
            }
        } else {
            panic!("help")
        }
    }

    fn random_message() -> [u8; 100] {
        let mut msg = [0u8; 100];
        (&mut rand::thread_rng()).fill_bytes(&mut msg);
        msg
    }
}
