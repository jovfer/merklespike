# merklespike
research on merkle trees for ZKP revocation in Hyperledger Ursa

## fillpart
When you run `cargo build --release`, a binary named `fillpart` is created in `target/release`. Run this app to experiment with different sizes and fill ratios of a merkle tree from Ursa.

DON'T RUN THIS ON A DEBUG BUILD; it's about 10x-100x slower and not useful for comparison.

## benchmarks
When you run `cargo bench`, you get analysis of the timing of various functions.
