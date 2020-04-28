use bulletproofs_amcl::{
    r1cs::gadgets::{
        helper_constraints::{
            sparse_merkle_tree_8_ary::{VanillaSparseMerkleTree8, DbVal8ary},
            poseidon::{PoseidonParams, SboxType}
        },
        merkle_tree_hash::PoseidonHash8
    },
    utils::hash_db::InMemoryHashDb
};
use amcl_wrapper::field_elem::FieldElement;
use std::io;
use std::io::Write;

extern crate jemalloc_ctl;
extern crate jemallocator;

/// The type used to store leaves of the merkle tree.
pub type Db = InMemoryHashDb::<DbVal8ary>;

// Very fast. Profiler says average 15 nanoseconds.
pub fn make_db() -> Db {
    Db::new()
}

// Comparatively slow. Profiler says average 2 milliseconds.
pub fn make_hash_params() -> PoseidonParams {
    let width = 9;
    // The following values are appropriate for any of the following curves:
    // bls381, bn254, secp256k1, and ed25519.
    let (full_b, full_e, partial_rounds) = (4, 4, 56);
    PoseidonParams::new(width, full_b, full_e, partial_rounds).unwrap()
}

// Super fast. Profiler says average 2 nanoseconds.
pub fn make_hash_func(hash_params: &PoseidonParams) -> i32 {
    let _x = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    0
}

// Pretty slow. Profiler says average 23 milliseconds when depth = 12.
// Time increase is linear with depth of tree:
// depth = 3 -- ave time = 6 ms
// depth = 6 -- ave time = 12 ms
// depth = 9 -- ave time = 18 ms
// depth = 12 -- ave time = 24 ms
pub fn make_tree(hash_func: &PoseidonHash8, tree_depth: usize, db: &mut Db) -> i32 {
    let _x = VanillaSparseMerkleTree8::new(hash_func, tree_depth, db).unwrap();
    0
}

fn byte_count_to_friendly(byte_count: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * KB;
    const GB: f64 = KB * MB;
    let fbyte_count = byte_count as f64;

    if fbyte_count > GB {
        format!("{:.1} GB", fbyte_count / GB)
    } else if fbyte_count > MB {
        format!("{:.1} MB", fbyte_count / MB)
    } else if fbyte_count > KB {
        format!("{:.1} KB", fbyte_count / KB)
    } else {
        format!("{} bytes", byte_count)
    }
}

pub fn get_net_allocated_memory(relative_to_base: usize) -> usize {
    // Force an updated of cached statistics.
    jemalloc_ctl::epoch::advance().unwrap();
    let a = jemalloc_ctl::stats::allocated::read().unwrap() - relative_to_base;
    a
}

pub fn get_allocated_memory() -> usize {
    get_net_allocated_memory(0)
}

pub fn memdump(milestone: &str, base_value: usize) -> usize {
    let a = get_net_allocated_memory(base_value);
    println!("At {}, using {} of memory.", milestone, &byte_count_to_friendly(a));
    a
}


pub fn experiment(depth: i32, fill_ratio: f64) {

    let start_allocated = memdump("start of experiment", 0);

    let mut db = make_db();

    let hash_params = make_hash_params();

    let hash_func = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    let mut tree = VanillaSparseMerkleTree8::new(&hash_func, depth as usize, &mut db).unwrap();

    let capacity = (8 as u64).pow(depth as u32);
    let insert_count = (capacity as f64 * fill_ratio) as u64;
    println!("Capacity of tree = {}; filling {}% or {}.", capacity, fill_ratio * 100.0, insert_count);

    use std::time::Instant;
    let now = Instant::now();
    for i in 1..insert_count {
        let s = FieldElement::from(i as u64);
        tree.update(&s, s.clone(), &mut db).unwrap();
        io::stdout().write_all(b".").ok();
        if i % 100 == 99 {
            io::stdout().write_all(b"\n").ok();
            memdump(&format!("{} nodes inserted", i + 1), start_allocated);
        }
        io::stdout().flush().ok();
    }

    println!("\nExperiment completed after {} milliseconds.", now.elapsed().as_millis());
    memdump("end of experiment", start_allocated);
}
