// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use bls12_381_sig::{PublicKey, SecretKey, APK};
use rand::RngCore;

#[test]
fn unsafe_sign_verify() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let msg = random_message();

    // Sign and verify.
    let sig = sk.unsafe_sign(&msg);
    let pk = PublicKey::new(&sk);
    assert!(pk.verify(&sig, &msg).is_ok());
}

#[test]
fn unsafe_sign_verify_incorrect_message() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let msg = random_message();

    let sig = sk.unsafe_sign(&msg);

    // Verify with a different message.
    let msg = random_message();
    let pk = PublicKey::new(&sk);
    assert!(pk.verify(&sig, &msg).is_err());
}

#[test]
fn unsafe_sign_verify_incorrect_pk() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let msg = random_message();

    let sig = sk.unsafe_sign(&msg);

    // Verify with a different public key.
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(&sk);
    assert!(pk.verify(&sig, &msg).is_err());
}

#[test]
fn safe_sign_verify() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(&sk);
    let msg = random_message();

    let sig = sk.sign(&pk, &msg);

    // Verification with the standard pk should fail.
    assert!(pk.verify(&sig, &msg).is_err());

    // Verification with the aggregated version should work.
    let apk = APK::new(&pk);
    assert!(apk.verify(&sig, &msg).is_ok());
}

#[test]
fn safe_sign_verify_incorrect_message() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(&sk);
    let msg = random_message();

    let sig = sk.sign(&pk, &msg);

    // Verification with a different message should fail.
    let apk = APK::new(&pk);
    let msg = random_message();
    assert!(apk.verify(&sig, &msg).is_err());
}

#[test]
fn safe_sign_verify_incorrect_apk() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(&sk);
    let msg = random_message();

    let sig = sk.sign(&pk, &msg);

    // Verification with another APK should fail.
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(&sk);
    let apk = APK::new(&pk);
    assert!(apk.verify(&sig, &msg).is_err());
}

#[test]
fn safe_sign_verify_aggregated() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(&sk);
    let msg = random_message();

    let mut agg_sig = sk.sign(&pk, &msg);

    let mut apk = APK::new(&pk);

    (0..10).for_each(|_| {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::new(&sk);
        let sig = sk.sign(&pk, &msg);
        agg_sig = agg_sig.aggregate(&[sig]);
        apk.add(&[pk]);
    });

    assert!(apk.verify(&agg_sig, &msg).is_ok());
}

#[test]
fn safe_sign_verify_aggregated_incorrect_message() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(&sk);
    let msg = random_message();

    let mut agg_sig = sk.sign(&pk, &msg);

    let mut apk = APK::new(&pk);

    (0..10).for_each(|_| {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::new(&sk);
        let sig = sk.sign(&pk, &msg);
        agg_sig = agg_sig.aggregate(&[sig]);
        apk.add(&[pk]);
    });

    // Verification should fail with a different message.
    let msg = random_message();
    assert!(apk.verify(&agg_sig, &msg).is_err());
}

#[test]
fn safe_sign_verify_aggregated_incorrect_apk() {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::new(&sk);
    let msg = random_message();

    let mut agg_sig = sk.sign(&pk, &msg);

    let mut apk = APK::new(&pk);

    (0..10).for_each(|_| {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::new(&sk);
        let sig = sk.sign(&pk, &msg);
        agg_sig = agg_sig.aggregate(&[sig]);
        apk.add(&[pk]);
    });

    // Verification with the wrong APK should fail.
    let apk = APK::new(&pk);
    assert!(apk.verify(&agg_sig, &msg).is_err());
}

fn random_message() -> [u8; 100] {
    let mut msg = [0u8; 100];
    (&mut rand::thread_rng()).fill_bytes(&mut msg);
    msg
}
