// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![feature(test)]

extern crate test;

#[cfg(test)]
mod benches {
    use dusk_bls12_381_sign::{PublicKey, SecretKey, APK};
    use rand::RngCore;
    use test::Bencher;

    #[bench]
    fn bench_sign_vulnerable(b: &mut Bencher) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let msg = random_message();
        b.iter(|| sk.sign_vulnerable(&msg));
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from(&sk);
        let msg = random_message();
        b.iter(|| sk.sign(&pk, &msg));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from(&sk);
        let msg = random_message();
        let sig = sk.sign_vulnerable(&msg);
        b.iter(|| pk.verify(&sig, &msg));
    }

    #[bench]
    fn bench_aggregate_sig(b: &mut Bencher) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let msg = random_message();
        let sig = sk.sign_vulnerable(&msg);
        let sig2 = sig.clone();
        b.iter(|| sig.aggregate(&[sig2]));
    }

    #[bench]
    fn bench_aggregate_pk(b: &mut Bencher) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = PublicKey::from(&sk);
        let mut apk = APK::from(&pk);
        let pk2 = pk.clone();
        b.iter(|| apk.aggregate(&[pk2]));
    }

    fn random_message() -> [u8; 100] {
        let mut msg = [0u8; 100];
        (&mut rand::thread_rng()).fill_bytes(&mut msg);
        msg
    }
}
