// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
fn main() {
    print!("{}", jwt_rust::mascot::banner(None));
    println!("svg bytes: {}", jwt_rust::mascot::svg().len());
}
