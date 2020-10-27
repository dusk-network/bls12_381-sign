// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{PublicKey, SecretKey, Signature, APK};
use libc::{c_int, c_uchar, size_t};
use std::slice;

const SK_SIZE: usize = 32;
const SIG_SIZE: usize = 48;
const PK_SIZE: usize = 96;

const BLS_OK: c_int = 0;
const BLS_INVALID_BYTES: c_int = 1;
const BLS_VERIFICATION_FAILED: c_int = 2;

#[no_mangle]
pub unsafe extern "C" fn generate_keys(keys_ptr: *mut u8) {
    let keys_slice = slice::from_raw_parts_mut(keys_ptr, SK_SIZE + PK_SIZE);
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::from(&sk);

    keys_slice[..SK_SIZE].copy_from_slice(&sk.to_bytes());
    keys_slice[SK_SIZE..].copy_from_slice(&pk.to_bytes());
}

#[no_mangle]
pub unsafe extern "C" fn sign(
    sk_ptr: *const [c_uchar; SK_SIZE],
    pk_ptr: *const [c_uchar; PK_SIZE],
    msg_ptr: *mut u8,
    msg_len: size_t,
    sig_ptr: *mut u8,
) -> c_int {
    let sk = match SecretKey::from_bytes(&*sk_ptr) {
        Ok(sk) => sk,
        Err(_) => return BLS_INVALID_BYTES,
    };

    let pk = match PublicKey::from_bytes(&*pk_ptr) {
        Ok(pk) => pk,
        Err(_) => return BLS_INVALID_BYTES,
    };

    let msg = slice::from_raw_parts(msg_ptr, msg_len);

    let sig = sk.sign(&pk, &msg);
    let sig_slice = slice::from_raw_parts_mut(sig_ptr, SIG_SIZE);
    sig_slice.copy_from_slice(&sig.to_bytes());
    BLS_OK
}

#[no_mangle]
pub unsafe extern "C" fn verify(
    apk_ptr: *const [c_uchar; PK_SIZE],
    sig_ptr: *const [c_uchar; SIG_SIZE],
    msg_ptr: *mut u8,
    msg_len: size_t,
) -> c_int {
    let apk = match APK::from_bytes(&*apk_ptr) {
        Ok(apk) => apk,
        Err(_) => return BLS_INVALID_BYTES,
    };

    let sig = match Signature::from_bytes(&*sig_ptr) {
        Ok(sig) => sig,
        Err(_) => return BLS_INVALID_BYTES,
    };

    let msg = slice::from_raw_parts(msg_ptr, msg_len);

    match apk.verify(&sig, &msg).is_ok() {
        true => BLS_OK,
        false => BLS_VERIFICATION_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn create_apk(
    pk_ptr: *const [c_uchar; PK_SIZE],
    apk_ptr: *mut u8,
) -> c_int {
    let pk = match PublicKey::from_bytes(&*pk_ptr) {
        Ok(pk) => pk,
        Err(_) => return BLS_INVALID_BYTES,
    };

    let apk_slice = slice::from_raw_parts_mut(apk_ptr, PK_SIZE);
    apk_slice.copy_from_slice(&APK::from(&pk).to_bytes());
    BLS_OK
}

#[no_mangle]
pub unsafe extern "C" fn aggregate_pk(
    apk_ptr: *const [c_uchar; PK_SIZE],
    pk_ptr: *mut u8,
    pk_len: size_t,
    ret_ptr: *mut u8,
) -> c_int {
    let mut apk = match APK::from_bytes(&*apk_ptr) {
        Ok(apk) => apk,
        Err(_) => return BLS_INVALID_BYTES,
    };

    let pk_slice = slice::from_raw_parts(pk_ptr, pk_len);
    let pks: Vec<PublicKey> = pk_slice
        .chunks(PK_SIZE)
        .map(|bytes| {
            let mut arr = [0u8; PK_SIZE];
            arr.copy_from_slice(&bytes);
            PublicKey::from_bytes(&arr).expect("Invalid public key bytes")
        })
        .collect();

    apk.aggregate(&pks);
    let apk_slice = slice::from_raw_parts_mut(ret_ptr, PK_SIZE);
    apk_slice.copy_from_slice(&apk.to_bytes());
    BLS_OK
}

#[no_mangle]
pub unsafe extern "C" fn aggregate_sig(
    sig_ptr: *const [c_uchar; SIG_SIZE],
    sigs_ptr: *mut u8,
    sigs_len: size_t,
    ret_ptr: *mut u8,
) -> c_int {
    let sig = match Signature::from_bytes(&*sig_ptr) {
        Ok(sig) => sig,
        Err(_) => return BLS_INVALID_BYTES,
    };

    let sig_slice = slice::from_raw_parts(sigs_ptr, sigs_len);
    let sigs: Vec<Signature> = sig_slice
        .chunks(SIG_SIZE)
        .map(|bytes| {
            let mut arr = [0u8; SIG_SIZE];
            arr.copy_from_slice(&bytes);
            Signature::from_bytes(&arr).expect("Invalid signature bytes")
        })
        .collect();

    let sig = sig.aggregate(&sigs);
    let sig_slice = slice::from_raw_parts_mut(ret_ptr, SIG_SIZE);
    sig_slice.copy_from_slice(&sig.to_bytes());
    BLS_OK
}
