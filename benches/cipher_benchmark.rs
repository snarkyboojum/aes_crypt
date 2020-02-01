use aes_crypt::{cipher, expand_key, KeyLength};
use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
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

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
