// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![feature(test)]

extern crate test;

mod benches {
    use dusk_bls12_381_sign::{PublicKey, SecretKey, APK};
    use rand_core::{OsRng, RngCore};
    use test::Bencher;

    #[bench]
    fn bench_sign_vulnerable(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let msg = random_message();
        b.iter(|| sk.sign_vulnerable(&msg));
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);
        let msg = random_message();
        b.iter(|| sk.sign(&pk, &msg));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);
        let msg = random_message();
        let sig = sk.sign_vulnerable(&msg);
        b.iter(|| pk.verify(&sig, &msg));
    }

    #[bench]
    fn bench_aggregate_sig(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let msg = random_message();
        let sig = sk.sign_vulnerable(&msg);
        b.iter(|| sig.aggregate(&[sig]));
    }

    #[bench]
    fn bench_aggregate_pk(b: &mut Bencher) {
        let sk = SecretKey::random(&mut OsRng);
        let pk = PublicKey::from(&sk);
        let mut apk = APK::from(&pk);
        b.iter(|| apk.aggregate(&[pk]));
    }

    fn random_message() -> [u8; 100] {
        let mut msg = [0u8; 100];
        (&mut OsRng::default()).fill_bytes(&mut msg);
        msg
    }
}
