use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use vantage_hash::TripleHash;

fn bench_compute(c: &mut Criterion) {
    let sizes: &[usize] = &[32, 256, 1_024, 64 * 1_024, 1_024 * 1_024];

    let mut group = c.benchmark_group("TripleHash::compute");
    for &size in sizes {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| TripleHash::compute(black_box(d)));
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let data = vec![0u8; 1_024];
    let hash = TripleHash::compute(&data);

    c.bench_function("TripleHash::verify 1KB", |b| {
        b.iter(|| TripleHash::verify(black_box(&data), black_box(&hash)));
    });
}

fn bench_hex(c: &mut Criterion) {
    let hash = TripleHash::compute(b"bench hex encoding");
    c.bench_function("TripleHash::hex", |b| {
        b.iter(|| black_box(hash.hex()));
    });
}

fn bench_from_hex(c: &mut Criterion) {
    let hash = TripleHash::compute(b"bench from_hex");
    let hex_str = hash.hex();
    c.bench_function("TripleHash::from_hex", |b| {
        b.iter(|| TripleHash::from_hex(black_box(&hex_str)).unwrap());
    });
}

criterion_group!(
    benches,
    bench_compute,
    bench_verify,
    bench_hex,
    bench_from_hex
);
criterion_main!(benches);
