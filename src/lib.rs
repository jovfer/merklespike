use bulletproofs_amcl::{
    r1cs::gadgets::{
        helper_constraints::{
            sparse_merkle_tree_8_ary::{VanillaSparseMerkleTree8, DbVal8ary},
            poseidon::{PoseidonParams, SboxType},
        },
        merkle_tree_hash::PoseidonHash8,
    },
    utils::hash_db::InMemoryHashDb,
};
use amcl_wrapper::field_elem::FieldElement;
use std::io;
use std::io::Write;
use bulletproofs_amcl::r1cs::gadgets::merkle_tree_hash::Arity8MerkleTreeHash;
use crate::bitmap::Bitmap;
use std::collections::VecDeque;

mod bitmap;

extern crate jemalloc_ctl;
extern crate jemallocator;

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

pub fn experiment(depth: usize, fill_ratio: f64) {

    let start_allocated = memdump("start of experiment", 0);

    let mut db = make_db();

    let hash_params = make_hash_params();

    let hash_func = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    let mut tree = VanillaSparseMerkleTree8::new(&hash_func, depth as usize, &mut db).unwrap();

    // How many leaf nodes does this tree have?
    let capacity = (8 as u64).pow(depth as u32);
    // So, given the desired fill ratio, how many inserts should we do?
    let insert_count = (capacity as f64 * fill_ratio) as u64;
    use rand::distributions::{Distribution, Uniform};
    let dist = Uniform::from(0..capacity);

    println!("Capacity of tree = {}; filling {}% or {}.", capacity, fill_ratio * 100.0, insert_count);

    use std::time::Instant;
    let now = Instant::now();
    let mut rng = rand::thread_rng();
    for i in 0..insert_count {
        let s = FieldElement::from(dist.sample(&mut rng));
        tree.update(&s, FieldElement::one(), &mut db).unwrap();
        io::stdout().write_all(b".").ok();
        if i % 100 == 99 {
            io::stdout().write_all(b"\n").ok();
            memdump(&format!("{} nodes inserted", i + 1), start_allocated);
        }
        io::stdout().flush().ok();
    }

    let elapsed = now.elapsed().as_millis();
    println!("\nFill experiment completed after {} milliseconds ({} millis / insert).",
             elapsed, (elapsed as f64) / (insert_count as f64));
    println!("{} nodes now in tree.", db.len());
    memdump("end of fill experiment", start_allocated);

    use std::path::Path;
    let path = Path::new("/tmp/x.zip");
    let now = Instant::now();
    db.save(path, &tree.root).ok();
    let elapsed = now.elapsed().as_millis();
    println!("Saved and compressed file in {} millis.", elapsed);

    use std::fs;
    let uncompressed_size = 432 * db.len();
    let compressed_size = fs::metadata(path).unwrap().len();
    let compression_ratio = 1.0 - (compressed_size as f64 / uncompressed_size as f64);

    println!("Saved hashdb ({} bytes) to compressed file {} ({} bytes; {:.1}% compression).",
             uncompressed_size, path.display(), compressed_size, compression_ratio * 100.0);

    let mut db2 = Db::new();
    let now = Instant::now();
    let root2 = db2.load(path).unwrap();
    let elapsed = now.elapsed().as_millis();
    println!("Loading db back from disk took {} millis.", elapsed);
    if root2.eq(&tree.root) {
        if db2.len() == db.len() {
            println!("Integrity check passed.");
        } else {
            println!("Databases aren't the same size (original={}, reconstituted={}).",
                db.len(), db2.len());
        }
    } else {
        println!("Roots changed.");
    }

    let now = Instant::now();
    let mut revlist = bitmap::Bitmap::new(capacity as usize).unwrap();
    for _ in 0..insert_count {
        revlist.set_bit(dist.sample(&mut rng) as usize);
    }
    let elapsed = now.elapsed().as_millis();
    println!("Set {} bits in bitmap in {} millis.", insert_count, elapsed);

    let mut db = make_db();
    let hash_params = make_hash_params();
    let hash_func = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    let now = Instant::now();
    let _tree2 = build_tree_from_bitmap(depth, &revlist, &hash_func, &mut db);
    println!("Built tree from bitmap in {} millis.", now.elapsed().as_millis());
}

fn build_tree_from_bitmap<'a>(
    depth: usize, b: &bitmap::Bitmap,
    hash_func: &'a PoseidonHash8,
    db: &mut Db) -> Tree<'a> {

    use bulletproofs_amcl::r1cs::gadgets::merkle_tree_hash::Arity8MerkleTreeHash;
    use bulletproofs_amcl::utils::hash_db::HashDb;

    // Create a tree of the right depth. This will prepopulate the hash db with the hashes
    // of the 1- and 0-bit leaf nodes, plus all parents of those up to root.
    let mut tree = VanillaSparseMerkleTree8::new(
        hash_func, depth as usize, db).unwrap();

    //struct PossiblyOwnedFieldElement {
    //    FieldElement *;
    //    owned;
    //}
    let capacity: usize = 8_u32.pow((depth - 1) as u32) as usize;
    assert!(capacity*8 == b.len());
    let mut children_at_prev_level: Vec<FieldElement> = Vec::with_capacity(capacity);
    // Create the value that represents 1 set bit.
    let one = FieldElement::one();
    // Create the most common set of children we're going to see.
    let all_zeros: DbVal8ary = [
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
    ];
    // Figure out what the hash of all zeros is. We'll use this so often that it's
    // worth caching.
    let hash_all_zeros = hash_func.hash(all_zeros.to_vec()).unwrap();
    let mut i = 0;
    loop {
        let next8 = b.get_byte_for_bit(i);
        // If any bits are set...
        if next8 > 0 {
            let mut siblings = all_zeros.clone();
            let mut sibling_index = 0;
            for j in i..i+8 {
                if b.get_bit(j) {
                    siblings[sibling_index] = one.clone();
                }
                sibling_index += 1;
            }
            let this_hash = hash_func.hash(siblings.to_vec()).unwrap();
            children_at_prev_level.push(this_hash.clone());
            let this_hash_bytes = this_hash.to_bytes();
            if !db.contains_key(&this_hash_bytes) {
                db.insert(this_hash_bytes, siblings);
            }
        } else {
            // Nothing to do. All vacant leaf nodes already exist in the sparse tree.
            children_at_prev_level.push(hash_all_zeros.clone());
        }
        i += 8;
        if i >= b.len() {
            break;
        }
    }

    for _level in (2..depth).rev() {
        let children_at_this_level = children_at_prev_level;
        children_at_prev_level = Vec::new();
        let mut i = children_at_this_level.len() - 8;
        loop {
            let siblings = &children_at_this_level.as_slice()[i..i+8];
            let this_hash = hash_func.hash(siblings.to_vec()).unwrap();
            children_at_prev_level.push(this_hash.clone());
            let this_hash_bytes = this_hash.to_bytes();
            if !db.contains_key(&this_hash_bytes) {
                let array: DbVal8ary = [
                    siblings[0].clone(),
                    siblings[1].clone(),
                    siblings[2].clone(),
                    siblings[3].clone(),
                    siblings[4].clone(),
                    siblings[5].clone(),
                    siblings[6].clone(),
                    siblings[7].clone(),
                ];
                db.insert(this_hash_bytes, array);
            }
            if i == 0 {
                break;
            }
            i -= 8;
        }
        children_at_prev_level.reverse();
    }
    tree.root = hash_func.hash(children_at_prev_level).unwrap();
    tree
    //Tree::new_from_precomputed(&hash_func, depth, &root).unwrap()
}

struct PartialCachedTree<'a> {
    pub db: Db,
    pub tree: Tree<'a>,
    pub cached_lvl: Vec<FieldElement>,
    pub lvl_idx_to_cache: usize,
    pub leaf_bitmap: Bitmap,
    //TODO my_idx
}

impl PartialCachedTree<'_> {
    pub fn new_from_bitmap<'a>(hash_func: &'a PoseidonHash8, bitmap: Bitmap, lvl_idx_to_cache: usize, depth: usize) -> PartialCachedTree<'a> {
        let mut db = make_db();

        use bulletproofs_amcl::r1cs::gadgets::merkle_tree_hash::Arity8MerkleTreeHash;
        use bulletproofs_amcl::utils::hash_db::HashDb;

        // Create a tree of the right depth. This will prepopulate the hash db with the hashes
        // of the 1- and 0-bit leaf nodes, plus all parents of those up to root.
        let mut tree = VanillaSparseMerkleTree8::new(
            hash_func, depth as usize, &mut db).unwrap();

        //struct PossiblyOwnedFieldElement {
        //    FieldElement *;
        //    owned;
        //}
        let capacity: usize = 8_u32.pow((depth - 1) as u32) as usize;
        assert_eq!(capacity * 8, bitmap.len());
        let mut children_at_prev_level: Vec<FieldElement> = Vec::with_capacity(capacity);
        // Create the value that represents 1 set bit.
        let one = FieldElement::one();
        // Create the most common set of children we're going to see.
        let all_zeros: DbVal8ary = [
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
        ];
        // Figure out what the hash of all zeros is. We'll use this so often that it's
        // worth caching.
        let hash_all_zeros = hash_func.hash(all_zeros.to_vec()).unwrap();
        let mut i = 0;
        loop {
            let next8 = bitmap.get_byte_for_bit(i);
            // If any bits are set...
            if next8 > 0 {
                let mut siblings = all_zeros.clone();
                let mut sibling_index = 0;
                for j in i..i + 8 {
                    if bitmap.get_bit(j) {
                        siblings[sibling_index] = one.clone();
                    }
                    sibling_index += 1;
                }
                let this_hash = hash_func.hash(siblings.to_vec()).unwrap();
                children_at_prev_level.push(this_hash.clone());
                let this_hash_bytes = this_hash.to_bytes();
                if !db.contains_key(&this_hash_bytes) {
                    db.insert(this_hash_bytes, siblings);
                }
            } else {
                // Nothing to do. All vacant leaf nodes already exist in the sparse tree.
                children_at_prev_level.push(hash_all_zeros.clone());
            }
            i += 8;
            if i >= bitmap.len() {
                break;
            }
        }

        let mut cached_lvl = Vec::new();
        for _level in (2..depth).rev() {
            // println!("\nchildren_at_prev_level {:?}\n", &children_at_prev_level.as_slice()[0..2]);

            let children_at_this_level = children_at_prev_level;
            if _level == (depth - lvl_idx_to_cache) {
                cached_lvl = children_at_this_level.clone();
            }
            children_at_prev_level = Vec::new();
            let next_cnt = children_at_this_level.len() / 8;
            for i in 0..next_cnt {
                let siblings = &children_at_this_level.as_slice()[i*8..i*8 + 8];
                let this_hash = hash_func.hash(siblings.to_vec()).unwrap();
                children_at_prev_level.push(this_hash.clone());
                let this_hash_bytes = this_hash.to_bytes();
                if !db.contains_key(&this_hash_bytes) {
                    let array: DbVal8ary = [
                        siblings[0].clone(),
                        siblings[1].clone(),
                        siblings[2].clone(),
                        siblings[3].clone(),
                        siblings[4].clone(),
                        siblings[5].clone(),
                        siblings[6].clone(),
                        siblings[7].clone(),
                    ];
                    db.insert(this_hash_bytes, array);
                }
//                if i == 0 {
//                    break;
//                }
//                i -= 8;
            }
//            children_at_prev_level.reverse();
        }
        tree.root = hash_func.hash(children_at_prev_level).unwrap();
        PartialCachedTree {
            tree,
            cached_lvl,
            lvl_idx_to_cache: lvl_idx_to_cache,
            db,
            leaf_bitmap: bitmap,
        }
    }


    pub fn update_tree(&mut self, bitmap: &bitmap::Bitmap, idx_to_set: usize) {
        let mut db = make_db();
        let cached_lvl = &mut self.cached_lvl;
        let tree = &mut self.tree;
        let cache_bucket_sz = 1 << (3 * self.lvl_idx_to_cache);
        let bucket_num = idx_to_set / cache_bucket_sz;
        let bucket_offset = bucket_num * cache_bucket_sz;

        let mut bucket_bitmap = bitmap::Bitmap::new(cache_bucket_sz).unwrap();
        let mut idx = bucket_offset;
        for bucket_idx in 0..cache_bucket_sz {
            if bitmap.get_bit(idx) { //TODO copy by word or by byte
                bucket_bitmap.set_bit(bucket_idx);
            }
            idx += 1;
        }
        bucket_bitmap.set_bit(idx_to_set - bucket_offset);

        let sub_tree = build_tree_from_bitmap(self.lvl_idx_to_cache, &bucket_bitmap, &tree.hash_func, &mut db);
        cached_lvl[bucket_num] = sub_tree.root;

        let mut hashes: VecDeque<FieldElement> = cached_lvl.clone().into();
        while hashes.len() > 1 {
            let sublings: Vec<FieldElement> = hashes.drain(0..8).collect();
            hashes.push_back(tree.hash_func.hash(sublings).unwrap());
        }

        tree.root = hashes.remove(0).unwrap();
        self.db = db;
        self.leaf_bitmap.set_bit(idx_to_set);
    }
        // println!("Bitmap    {:?}\nBucket BM {:?}", bitmap, bucket_bitmap);
        // println!("Cached {:?}", cached_lvl);
        // println!("path {:?}", path);
        // println!("Sub-tree {:?}", sub_tree.root);
        // println!("idx {:?}", range_idx);
        // assert_eq!(sub_tree.root, cached_lvl[bucket_num]);

}

// ------------------------------------------------------------------
// The functions below are mainly used for benchmarking. They're designed
// to isolate particular pieces of logic that might perform in interesting
// ways. They are NOT very good functions to use for general merkle tree
// coding, because they encapsulate things in odd ways to make performance
// tests as crisp as possible.

/// The type used to store leaves of the merkle tree.
pub type Db = InMemoryHashDb::<DbVal8ary>;
pub type El = FieldElement;

pub type Tree<'a> = VanillaSparseMerkleTree8<'a, PoseidonHash8<'a>>;

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
pub fn make_hash_func(hash_params: &PoseidonParams) -> PoseidonHash8 {
    let hf = PoseidonHash8 {
        params: &hash_params,
        sbox: &SboxType::Quint,
    };
    hf
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

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod tests {


    use crate::{build_tree_from_bitmap, make_hash_func, make_hash_params, make_db, Tree, PartialCachedTree};
    use crate::bitmap::Bitmap;
    use amcl_wrapper::field_elem::FieldElement;
    use std::time::SystemTime;
/*
    #[test]
    fn build_from_bitmap_works() {
        let depth = 7;

        let mut bm = Bitmap::new(1 << (3*depth)).unwrap();
        let hash_params = make_hash_params();
        let poseidon_hash8 = make_hash_func(&hash_params);
        let mut db = make_db();
        let mut tree = Tree::new(&poseidon_hash8,depth, &mut db).unwrap();

        for idx in [1, 8+2, 8*8+3, 8*8*8+4].to_vec() {
            println!("iter for idx {:?}, \tstart at \t{:?}", idx, SystemTime::now());
        // for idx in [8*8*8usize+2, 1, 3, 28, 8*8usize+1, 8*8*8*8*8usize+4, 16166].to_vec() {
        // { let idx = 4608;
            bm.set_bit(idx);
            tree.update(&FieldElement::from(idx as u64), FieldElement::one(), &mut db);
            println!("iter for idx {:?}, \tupdated at \t{:?}", idx, SystemTime::now());
            let mut tree_from_bm = build_tree_from_bitmap(depth, &bm, &poseidon_hash8, &mut db);
            println!("iter for idx {:?}, \tbitmap at \t{:?}", idx, SystemTime::now());
            assert_eq!(tree.root, tree_from_bm.root);
            update_tree(&bm, idx, &mut tree_from_bm);
            println!("iter for idx {:?}, \tpartbld at \t{:?}", idx, SystemTime::now());
        }
    }
*/
    #[test]
    fn update_tree_from_bm_works() {
        println!("Start at test \t \t \t \t \t{:?}", SystemTime::now());
        let depth = 7;
        let lvl_to_cache = 4;

        let mut bm = Bitmap::new(1 << (3 * depth)).unwrap();
        let hash_params = make_hash_params();
        let poseidon_hash8 = make_hash_func(&hash_params);
        let mut db = make_db();
        println!("Preparation fs \t \t \t \t \t{:?}", SystemTime::now());
        let mut tree = Tree::new(&poseidon_hash8, depth, &mut db).unwrap();
        println!("New tree built \t \t \t \t \t{:?}", SystemTime::now());
        let mut tree_from_bm = PartialCachedTree::new_from_bitmap(&poseidon_hash8, bm.clone(), lvl_to_cache, depth);
        println!("Tree from bmap \t \t \t \t \t{:?}", SystemTime::now());

        for idx in [1, 8 + 2, 8 * 8 + 3, 8 * 8 * 8 + 4].to_vec() {
            println!("iter for idx {:?}, \tstart at \t{:?}", idx, SystemTime::now());
            // for idx in [8*8*8usize+2, 1, 3, 28, 8*8usize+1, 8*8*8*8*8usize+4, 16166].to_vec() {
            // { let idx = 4608;
            bm.set_bit(idx);
            tree.update(&FieldElement::from(idx as u64), FieldElement::one(), &mut db).unwrap();
            println!("iter for idx {:?}, \tupdated at \t{:?}", idx, SystemTime::now());

            tree_from_bm.update_tree(&bm, idx);
            assert_eq!(tree.root, tree_from_bm.tree.root);
            println!("iter for idx {:?}, \tpartbld at \t{:?}", idx, SystemTime::now());
        }
    }

    use super::memdump;
    #[test]
    fn load_pct_build_works() {
        let start_mem = memdump("Init", 0);
        println!("PC tree prep  \t \t \t \t \t{:?}", SystemTime::now());
        let depth = 7;
        let cache_lvl = 4;
        let hash_params = make_hash_params();
        let poseidon_hash8 = make_hash_func(&hash_params);
        use rand::distributions::{Distribution, Uniform};
        let capacity = 1 << (3*depth); // 8^depth
        let insert_count = capacity / 10;
        let dist = Uniform::from(0..capacity);
        let mut rng = rand::thread_rng();
        let mut revlist = Bitmap::new(capacity as usize).unwrap();
        for _ in 0..insert_count {
            revlist.set_bit(dist.sample(&mut rng) as usize);
        }

        println!("PC tree start  \t \t \t \t \t{:?}", SystemTime::now());
        memdump("After prep", start_mem);
        let mut partial_cached_tree = PartialCachedTree::new_from_bitmap(&poseidon_hash8, revlist.clone(), cache_lvl, depth);
        println!("PC tree finish \t \t \t \t \t{:?}", SystemTime::now());
        memdump("After build", start_mem);
        partial_cached_tree.update_tree(&revlist, 0);
        println!("PC tree updtd \t \t \t \t \t{:?}", SystemTime::now());
        memdump("After upd", start_mem);
        partial_cached_tree.update_tree(&revlist, 1025);
        println!("PC tree upd 2 \t \t \t \t \t{:?}", SystemTime::now());
        memdump("After upd 2", start_mem);
    }
}

