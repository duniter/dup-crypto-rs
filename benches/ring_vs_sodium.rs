use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dup_crypto::seeds::Seed32;
use ring::signature::Ed25519KeyPair as RingKeyPair;
use sodiumoxide::crypto::sign;

const MESSAGE: &[u8] = b"azedjlazifjs dleufxmjz jfmjfmljrfmlgc jzlamu^^^^^^^^^^^^^^^^^^^^^ssssssssssssssssssssssss\
ssssssssssssszaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa541368630...5.31873679387azqszxdxs<dzdq ccg ill:;n: \
!   gjbtirglkrtnjbgkgbrl gjbtirglkrtnjbgkgbrl:lqjczo jlnkrhilhloiemoipo cjiothurhtgilrjumloc impiorjtiyhlilu*u*^&&";

fn ring_sign(ring_key_pair: &RingKeyPair) {
    ring_key_pair.sign(MESSAGE);
}

fn sodium_sign(sodium_secret_key: &sodiumoxide::crypto::sign::ed25519::SecretKey) {
    sign::sign(MESSAGE, &sodium_secret_key);
}

pub fn benchmark(c: &mut Criterion) {
    let ring_key_pair = RingKeyPair::from_seed_unchecked(
        Seed32::random().expect("fail to gen random seed").as_ref(),
    )
    .expect("fail to gen ring keypair");
    let (_, sodium_secret_key) = sign::gen_keypair();
    let mut group = c.benchmark_group("sign");
    group.bench_function("sodium_sign", |b| {
        b.iter(|| sodium_sign(black_box(&sodium_secret_key)))
    });
    group.bench_function("ring_sign", |b| {
        b.iter(|| ring_sign(black_box(&ring_key_pair)))
    });
    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
