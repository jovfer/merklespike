extern crate clap;
use clap::{Arg, App};

// Force this binary to use jemalloc. This is what allows us to
// get stats about memory usage.
extern crate jemallocator;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() {

    if cfg!(debug_assertions) {
        println!("\n\nWARNING: results will be invalid because you're using a debug build.\n\n");
    }

    let matches = App::new("fillpart")
        .about("\
        \nRuns an experiment that builds and partially fills a merkle tree structure, noting \
        the timing and memory consumption; writes the results to stdout. You can compare \
        different choices by running the experiment multiple times, using different inputs.")
        .arg(Arg::with_name("depth")
            .short("d")
            .long("depth")
            .value_name("N")
            .help("Sets depth of merkle tree")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("fill-ratio")
            .short("f")
            .long("fill-ratio")
            .value_name("X")
            .help("How much of the merkle tree should be filled (0 to 1)")
            .required(true)
        ).get_matches();

    let depth: i32 = matches.value_of("depth").unwrap().parse::<i32>().unwrap();
    let fill_ratio: f64 = matches.value_of("fill-ratio").unwrap().parse::<f64>().unwrap();

    merklespike::experiment(depth, fill_ratio);
}
