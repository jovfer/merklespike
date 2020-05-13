extern crate clap;
use clap::{Arg, App};
use bulletproofs_amcl::r1cs::gadgets::helper_constraints::sparse_merkle_tree_8_ary::DbVal8ary;
use std::io;
use std::io::Write;

#[macro_use] extern crate lazy_static;

// Force this binary to use jemalloc. This is what allows us to
// get stats about memory usage.
extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use merklespike::{El, Db, Tree};

fn main() {

    let matches = App::new("treewalk")
        .about("\
        \nbuilds a tree and lets you inspect it.")
        .arg(Arg::with_name("depth")
            .short("d")
            .long("depth")
            .value_name("N")
            .help("Sets depth of merkle tree")
            .takes_value(true))
        .get_matches();

    let depth: usize = matches.value_of("depth").unwrap_or("2").parse::<usize>().unwrap();

    let mut db = merklespike::make_db();
    let hash_params = merklespike::make_hash_params();
    let hash_func = merklespike::make_hash_func(&hash_params);
    let mut tree = merklespike::Tree::new(
        &hash_func, depth as usize, &mut db).unwrap();

    println!("Generated a sparse 8-ary Merkle tree.\n  depth = {}\n  node count = {}",
            depth, db.len());

    let mut last_path = "root".to_string();
    let mut path = "".to_string();
    let mut short_circuit = true;
    loop {
        io::stdout().write(format!("\n{}> ", last_path).as_bytes()).ok();
        io::stdout().flush().ok();
        let mut cmd = String::new();
        // Skip input first time through loop; always show root of tree
        if short_circuit {
            cmd = last_path.clone();
            io::stdout().write(b"root\n").ok();
            short_circuit = false;
        } else {
            if io::stdin().read_line(&mut cmd).is_err() {
                break;
            }
        }
        let token = cmd.trim();
        if let Ok(child_num ) = token.parse::<u8>() {
            if child_num < 8 {
                path = last_path.clone();
                path.push('/');
                path.push_str(token);
            } else {
                println!("No such child.");
                continue
            }
        } else if token.starts_with('/') {
            path = token.to_string();
        } else if token.starts_with("i ") {
            let idx = token[2..].parse::<u64>().unwrap();
            tree.update(&El::from(idx), El::one(), &mut db).ok();
            path = last_path.clone();
        } else {
            match token {
                "up" => {
                    if let Some(i) = last_path.rfind('/') {
                        path = last_path[..i].to_string();
                    }
                },
                "root" => {
                    path = token.to_string();
                },
                "help" => {
                    println!("Enter \"up\", \"quit\", child num, or abs path like /1/3/7: ");
                    continue
                },
                "quit" => return,
                "q" => return,
                _ => {
                    println!("Huh?");
                    continue
                }
            }
        }
        if let Some((preamble, node)) = find_node_from_path(&tree, &db, path.as_str()) {
            last_path = path.clone();
            dump(Some(preamble), &node, &db);
        } else {
            println!("No such path.");
        }
    }
}


fn dump(preamble: Option<Vec<PathSegment>>, key: &El, db: &Db) {
    let mut indenter = "".to_string();
    if let Some(preamble) = preamble {
        for item in preamble {
            let delim = if indenter.len() == 0 { "" } else { "/" };
            println!("{}{}{} = {}", indenter, delim, item.descrip, item.key);
            indenter.push_str("  ");
        }
    }
    if let Some(node) = get_node(key, db) {
        indenter.push_str(" ");
        println!("{}  |", indenter.as_str());
        if has_children(&node) {
            for i in 0..8 {
                let more_txt = if found_with_children(&node[i], db) { "+" } else { "-" };
                println!("{}{} {}: {}", indenter, more_txt, i, get_key_text(&node[i], false));
            }
        } else {
            println!("{}  .", indenter.as_str());
        }
    } else {
        println!("{} not found in map!", get_key_text(key, false));
    }
}

fn get_node(el: & El, db: & Db) -> Option<DbVal8ary> {
    use bulletproofs_amcl::utils::hash_db::HashDb;
    if let Ok(r) = db.get(&el.to_bytes()) {
        Some(r)
    } else {
        None
    }
}

fn found_with_children(key: &El, db: & Db) -> bool {
    if let Some(node) = get_node(key, db) {
        return has_children(&node)
    }
    false
}

fn has_children(node: &DbVal8ary) -> bool {
    for i in 0..8 {
        if !node[i].is_zero() {
            return true
        }
    }
    false
}

fn get_key_text(el: &El, full: bool) -> String {
    if el.is_zero() {
        "0".to_string()
    } else {
        let hex = el.to_hex();
        if full {
            hex
        } else {
            format!("...{}", &hex[hex.len() - 8..])
        }
    }
}

struct PathSegment {
    pub descrip: String,
    pub key: String,
}

/// Given a human-entered path string like "/3/7", find the corresponding
/// internal path through the tree to the node, plus the FieldElement that
/// acts as the lookup key for the node.
fn find_node_from_path(tree: & Tree, db: & Db, path: &str) -> Option<(Vec<PathSegment>, El)> {
    use regex::Regex;

    lazy_static! {
        static ref RE: Regex = Regex::new(r"(\d+)").unwrap();
    }
    let mut lookup_key = tree.root.clone();
    let mut current= get_node(&lookup_key, &db).unwrap();
    let mut ids: Vec<PathSegment> = Vec::new();
    let mut segment_descrip = "root";
    let last = RE.find_iter(path).last();
    ids.push(PathSegment {
        descrip: segment_descrip.to_string(),
        key: get_key_text(&lookup_key, last.is_none())
    });
    for item in RE.find_iter(path) {
        segment_descrip = item.as_str();
        let child_idx: usize = item.as_str().parse().unwrap();
        if child_idx < 8 {
            lookup_key = current[child_idx].clone();
            if let Some(next) = get_node(&lookup_key, &db) {
                current = next;
                let is_last = if last.is_some() { item.eq(&last.unwrap()) } else { false };
                ids.push(PathSegment {
                    descrip: segment_descrip.to_string(),
                    key: get_key_text(&lookup_key, is_last)
                });
            } else {
                println!("Not found: {}.", &path[0..item.end()]);
                return None
            }
        } else {
            println!("Bad index {} in path.", child_idx);
        }
    }
    Some((ids, lookup_key.clone()))
}