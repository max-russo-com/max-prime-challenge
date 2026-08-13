fn main() {
    println!("========================================================================");
    println!("MAX PRIME CHALLENGE PUBLIC CLIENT");
    println!("========================================================================");
    println!();
    println!("This repository exposes two public binaries:");
    println!();
    println!("  1) max_prime_public_client");
    println!("     Command-line client for local tests and official server-assigned work.");
    println!();
    println!("  2) max_prime_public_gui");
    println!("     Desktop GUI for MAX Login, official work, nickname and logout.");
    println!();
    println!("Build:");
    println!("  cargo build --release");
    println!();
    println!("Run CLI:");
    println!("  ./target/release/max_prime_public_client official-config");
    println!("  ./target/release/max_prime_public_client official-participant-status");
    println!("  ./target/release/max_prime_public_client official-run-once <challenge_id>");
    println!();
    println!("Run GUI:");
    println!("  ./target/release/max_prime_public_gui");
    println!();
    println!("Engine note:");
    println!("  The public client computation engine uses dashu-int.");
    println!("  Older prototype BigInt code is not part of this public launcher.");
}
