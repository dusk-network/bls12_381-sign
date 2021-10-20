// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

#[cfg(feature = "std")]
pub struct BlsSigner {
    cache: Arc<RwLock<HashMap<[u8; 96], [u8; 193]>>>,
}

impl Default for BlsSigner {
    fn default() -> BlsSigner {
        BlsSigner {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[cfg(feature = "std")]
use {
    crate::aggregate_response::Agg::Code,
    crate::create_apk_response::Apk::Apk,
    crate::sign_response::Sig::Signature as ResponseSignature,
    crate::verify_response::Ver::Valid,
    crate::AggregatePkRequest,
    crate::AggregateResponse,
    crate::AggregateSigRequest,
    crate::CreateApkRequest,
    crate::CreateApkResponse,
    crate::GenerateKeysResponse,
    crate::SignRequest,
    crate::SignResponse,
    crate::VerifyRequest,
    crate::VerifyResponse,
    dusk_bls12_381_sign::{PublicKey, SecretKey, Signature, APK},
    tonic::{Request, Response, Status},
};

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
            <$wrapper>::from_bytes(unsafe { this_transmute(s) }).map_err(|_| {
                Status::invalid_argument(format!(
                    "unable to convert to type {}",
                    $note
                ))
            })
        }
    }};
}

#[cfg(feature = "std")]
impl BlsSigner {
    async fn public_from_cache(&self, pk: &[u8]) -> Result<PublicKey, Status> {
        let pk = BlsSigner::slice_to_fixed(pk)?;
        if let Some(o) = self.cache.read().await.get(&pk) {
            return PublicKey::from_raw_bytes(o).map_err(|_| {
                Status::invalid_argument("Invalid raw public key")
            });
        };
        let key = PublicKey::from_bytes(&pk)
            .map_err(|_| Status::invalid_argument("Invalid public key"))?;
        self.cache.write().await.insert(pk, key.to_raw_bytes());
        Ok(key)
    }

    async fn apk_from_cache(&self, apk: &[u8]) -> Result<APK, Status> {
        let apk_bytes = BlsSigner::slice_to_fixed(apk)?;
        if let Some(o) = self.cache.read().await.get(&apk_bytes) {
            return APK::from_raw_bytes(o).map_err(|_| {
                Status::invalid_argument("Invalid raw aggregated public key")
            });
        };
        let key = APK::from_bytes(&apk_bytes).map_err(|_| {
            Status::invalid_argument("Invalid aggregated public key")
        })?;
        self.cache
            .write()
            .await
            .insert(apk_bytes, key.to_raw_bytes());
        Ok(key)
    }

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

    /// Generate a new BLS12-381 key pair
    pub(crate) async fn generate_keys_sync(
        &self,
    ) -> Result<Response<GenerateKeysResponse>, Status> {
        // get a new random secret key from system entropy
        let sk = SecretKey::new(&mut rand_core::OsRng);
        let pk = PublicKey::from(&sk);
        let pk_bytes = pk.to_bytes();
        self.cache.write().await.insert(pk_bytes, pk.to_raw_bytes());
        // construct the gRPC response from the key and return it
        Ok(Response::new(GenerateKeysResponse {
            secret_key: sk.to_bytes().to_vec(),
            public_key: pk_bytes.to_vec(),
        }))
    }

    /// Sign a message using a provided BLS12-381 key pair
    pub(crate) async fn sign_sync(
        &self,
        request: &Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let sk = slice_as!(req.secret_key.as_slice(), SecretKey, "SecretKey")?;
        let pk = self.public_from_cache(&req.public_key).await?;
        let res =
            ResponseSignature(sk.sign(&pk, &req.message).to_bytes().to_vec());
        // return the signature wrapped in the response type
        Ok(Response::new(SignResponse { sig: Some(res) }))
    }

    /// Verify a BLS12-381 signature on a message with a given public key
    pub(crate) async fn verify_sync(
        &self,
        request: &Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let apk = self.apk_from_cache(&req.apk).await?;
        let sig = slice_as!(&req.signature, Signature, "Signature")?;

        // verify the message matches the signature and the signature matches the
        // given public key
        let res = apk.verify(&sig, &req.message);
        // return whether the verification returned no error
        Ok(Response::new(VerifyResponse {
            ver: Some(Valid(res.is_ok())),
        }))
    }

    /// Aggregate a collection of public keys to an aggregated public key
    pub(crate) async fn aggregate_pk_sync(
        &self,
        request: &Request<AggregatePkRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        // get the apk first
        let mut apk = self.apk_from_cache(&req.apk).await?;
        // collect the list of public keys into a vector
        let mut pks = Vec::with_capacity(req.keys.len());
        for elem in &req.keys {
            pks.push(self.public_from_cache(elem).await?);
        }
        // aggregate the keys
        apk.aggregate(&pks);
        // convert public key to aggregated public key and return it
        Ok(Response::new(AggregateResponse {
            agg: Some(Code(apk.to_bytes().to_vec())),
        }))
    }

    /// Create an aggregated public key from a public key
    pub(crate) async fn create_apk_sync(
        &self,
        request: &Request<CreateApkRequest>,
    ) -> Result<Response<CreateApkResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let pk = self.public_from_cache(&req.public_key).await?;
        let apk = APK::from(&pk);
        Ok(Response::new(CreateApkResponse {
            apk: Some(Apk(apk.to_bytes().to_vec())),
        }))
    }

    /// Aggregate a collection of signatures into an aggregated signature
    pub(crate) async fn aggregate_sig_sync(
        &self,
        request: &Request<AggregateSigRequest>,
    ) -> Result<Response<AggregateResponse>, Status> {
        // access the request parameters
        let req = request.get_ref();
        let sig = slice_as!(&req.signature, Signature, "Signature")?;

        // convert the raw bytes from the message to a collection of signatures
        let mut sigs: Vec<Signature> = Vec::with_capacity(req.signatures.len());
        // collect the list of public keys into a vector
        for elem in &req.signatures {
            sigs.push(slice_as!(elem, Signature, "Signature")?);
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
#[cfg(test)]
mod svc {
    pub use crate::sign_response::Sig::Signature as ResponseSignature;
    pub use crate::verify_response::Ver::Valid;
    pub use crate::*;
    pub use dusk_bls12_381_sign::{PublicKey, SecretKey, Signature, APK};
    pub use rand::RngCore;
    mod benches_svc {

        pub use super::*;
        extern crate test;
        use dusk_bls12_381_sign::{PublicKey, SecretKey};
        use test::Bencher;

        fn public_from_compressed_macro(s: &[u8]) -> Result<PublicKey, Status> {
            slice_as!(s, PublicKey, "PublicKey")
        }

        #[bench]
        fn bench_deser_compressed(b: &mut Bencher) {
            let sk = SecretKey::new(&mut rand::thread_rng());
            let bytes = PublicKey::from(&sk).to_bytes().to_vec();
            b.iter(|| public_from_compressed_macro(&bytes).unwrap());
        }

        #[bench]
        fn bench_deser_uncompressed(b: &mut Bencher) {
            let sk = SecretKey::new(&mut rand::thread_rng());
            let raw = PublicKey::from(&sk).to_raw_bytes().to_vec();
            b.iter(|| {
                PublicKey::from_raw_bytes(
                    &BlsSigner::slice_to_fixed(&raw).unwrap(),
                )
            });
        }
    }
}
