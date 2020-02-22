use aes_crypt::{cipher, expand_key, inverse_cipher, KeyLength};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn cipher_latency(c: &mut Criterion) {
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let expanded_key = &mut [0u32; 44];
    c.bench_function("expand_key test_key", |b| {
        b.iter(|| {
            expand_key(&key, expanded_key, KeyLength::OneTwentyEight);
        })
    });
    expand_key(&key, expanded_key, KeyLength::OneTwentyEight);
    c.bench_function("cipher test_data", |b| {
        b.iter(|| {
            let _output: [u8; 16] = cipher(&plaintext, expanded_key);
        })
    });
}

fn cipher_throughput(c: &mut Criterion) {
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    // expand the key once
    let expanded_key = &mut [0u32; 44];
    expand_key(&key, expanded_key, KeyLength::OneTwentyEight);

    let mut group = c.benchmark_group("cipher_throughput");
    group.throughput(Throughput::Bytes(plaintext.len() as u64));
    group.bench_function("cipher test_data", |b| {
        b.iter(|| {
            let _output: [u8; 16] = cipher(&plaintext, expanded_key);
        })
    });
    group.finish();
}

fn inverse_cipher_throughput(c: &mut Criterion) {
    let cipher_text: [u8; 16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let expanded_key = &mut [0u32; 44];
    expand_key(&key, expanded_key, KeyLength::OneTwentyEight);

    let mut group = c.benchmark_group("inverse_cipher_throughput");
    group.throughput(Throughput::Bytes(cipher_text.len() as u64));
    group.bench_function("inverse cipher test_data", |b| {
        b.iter(|| {
            let _output: [u8; 16] = inverse_cipher(&cipher_text, expanded_key);
        })
    });
    group.finish();
}

//criterion_group!(benches, cipher_latency);
criterion_group!(
    benches,
    cipher_latency,
    cipher_throughput,
    inverse_cipher_throughput
);
criterion_main!(benches);
