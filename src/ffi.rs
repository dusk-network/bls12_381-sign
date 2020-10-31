// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{Error, PublicKey, SecretKey, Signature, APK};
use libc::{c_int, c_uchar, size_t};
use std::{ptr, slice};

const SK_SIZE: usize = SecretKey::serialized_size();
const SIG_SIZE: usize = Signature::serialized_size();
const PK_SIZE: usize = PublicKey::serialized_size();

const BLS_OK: c_int = 0;

impl From<Error> for c_int {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidBytes => 1,
            Error::InvalidSignature => 2,
        }
    }
}

macro_rules! unwrap_or_bail {
    ( $e: expr ) => {
        match $e {
            Ok(v) => v,
            Err(e) => return e.into(),
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn generate_keys(sk_ptr: *mut u8, pk_ptr: *mut u8) {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::from(&sk);

    ptr::copy_nonoverlapping(&sk.to_bytes()[0] as *const u8, sk_ptr, SK_SIZE);
    ptr::copy_nonoverlapping(&pk.to_bytes()[0] as *const u8, pk_ptr, PK_SIZE);
}

#[no_mangle]
pub unsafe extern "C" fn sign(
    sk_ptr: *const [c_uchar; SK_SIZE],
    pk_ptr: *const [c_uchar; PK_SIZE],
    msg_ptr: *mut u8,
    msg_len: size_t,
    sig_ptr: *mut u8,
) -> c_int {
    let sk = unwrap_or_bail!(SecretKey::from_bytes(&*sk_ptr));
    let pk = unwrap_or_bail!(PublicKey::from_bytes(&*pk_ptr));

    let msg = slice::from_raw_parts(msg_ptr, msg_len);

    let sig = sk.sign(&pk, &msg);
    ptr::copy_nonoverlapping(
        &sig.to_bytes()[0] as *const u8,
        sig_ptr,
        SIG_SIZE,
    );
    BLS_OK
}

#[no_mangle]
pub unsafe extern "C" fn verify(
    apk_ptr: *const [c_uchar; PK_SIZE],
    sig_ptr: *const [c_uchar; SIG_SIZE],
    msg_ptr: *mut u8,
    msg_len: size_t,
) -> c_int {
    let apk = unwrap_or_bail!(APK::from_bytes(&*apk_ptr));
    let sig = unwrap_or_bail!(Signature::from_bytes(&*sig_ptr));

    let msg = slice::from_raw_parts(msg_ptr, msg_len);

    match apk.verify(&sig, &msg).is_ok() {
        true => BLS_OK,
        false => Error::InvalidSignature.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn create_apk(
    pk_ptr: *const [c_uchar; PK_SIZE],
    apk_ptr: *mut u8,
) -> c_int {
    let pk = unwrap_or_bail!(PublicKey::from_bytes(&*pk_ptr));

    let apk = APK::from(&pk);
    ptr::copy_nonoverlapping(&apk.to_bytes()[0] as *const u8, apk_ptr, PK_SIZE);
    BLS_OK
}

#[no_mangle]
pub unsafe extern "C" fn aggregate_pk(
    apk_ptr: *const [c_uchar; PK_SIZE],
    pk_ptr: *mut u8,
    pk_len: size_t,
    ret_ptr: *mut u8,
) -> c_int {
    let mut apk = unwrap_or_bail!(APK::from_bytes(&*apk_ptr));

    let pk_slice = slice::from_raw_parts(pk_ptr, pk_len);
    let pks: Result<Vec<PublicKey>, Error> = pk_slice
        .chunks(PK_SIZE)
        .map(|bytes| {
            let mut arr = [0u8; PK_SIZE];
            arr.copy_from_slice(&bytes);
            PublicKey::from_bytes(&arr)
        })
        .collect();

    let pks = unwrap_or_bail!(pks);
    apk.aggregate(&pks);
    ptr::copy_nonoverlapping(&apk.to_bytes()[0] as *const u8, ret_ptr, PK_SIZE);
    BLS_OK
}

#[no_mangle]
pub unsafe extern "C" fn aggregate_sig(
    sig_ptr: *const [c_uchar; SIG_SIZE],
    sigs_ptr: *mut u8,
    sigs_len: size_t,
    ret_ptr: *mut u8,
) -> c_int {
    let sig = unwrap_or_bail!(Signature::from_bytes(&*sig_ptr));

    let sig_slice = slice::from_raw_parts(sigs_ptr, sigs_len);
    let sigs: Result<Vec<Signature>, Error> = sig_slice
        .chunks(SIG_SIZE)
        .map(|bytes| {
            let mut arr = [0u8; SIG_SIZE];
            arr.copy_from_slice(&bytes);
            Signature::from_bytes(&arr)
        })
        .collect();

    let sigs = unwrap_or_bail!(sigs);
    let sig = sig.aggregate(&sigs);
    ptr::copy_nonoverlapping(
        &sig.to_bytes()[0] as *const u8,
        ret_ptr,
        SIG_SIZE,
    );
    BLS_OK
}
