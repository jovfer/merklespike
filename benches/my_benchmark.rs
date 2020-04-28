use criterion::{criterion_group, criterion_main, Criterion};
use bulletproofs_amcl::{
    r1cs::gadgets::{
        helper_constraints::{
            sparse_merkle_tree_8_ary::{VanillaSparseMerkleTree8, DbVal8ary, ProofNode8ary},
            poseidon::{PoseidonParams, SboxType}
        },
        merkle_tree_hash::PoseidonHash8
    },
    utils::hash_db::InMemoryHashDb
};

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("create Db", |b| b.iter(|| merklespike::make_db()));
    c.bench_function("create hash params", |b| b.iter(|| merklespike::make_hash_params()));

    let hash_params = merklespike::make_hash_params();
    c.bench_function("create hash func", |b| b.iter(|| merklespike::make_hash_func(&hash_params)));

    let mut db = merklespike::make_db();
    let hash_func = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    c.bench_function("make tree depth 3", |b| b.iter(|| merklespike::make_tree(&hash_func, 3, &mut db)));
    //c.bench_function("make tree depth 6", |b| b.iter(|| merklespike::make_tree(&hash_func, 6, &mut db)));
    //c.bench_function("make tree depth 9", |b| b.iter(|| merklespike::make_tree(&hash_func, 9, &mut db)));
    //c.bench_function("make tree depth 12", |b| b.iter(|| merklespike::make_tree(&hash_func, 12, &mut db)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);