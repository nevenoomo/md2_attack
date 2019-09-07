//! # MD2 hashing, compression and peimage calculation
//! 
//! A CLI application.
//! Usage: md2_attack MODE BLOCKS
//!     MODE:
//!         md2      - return digest
//!         compress - return the result of compression of a message block
//!                    from ARGS and a compressing block from ARGS
//!         preimage - find preimage of a given message
//!     ARGS:
//!         block    - ex. "1 2 3 0 1 2 3 0 1 2 3 0 1 2 3 0"

use std::env;
use std::vec::Vec;
use std::string::String;
use std::iter::Iterator;

fn main() {
    let mut args = env::args().skip(1); // skipping the name of the program

    let mode = args.next().expect("Mode expected as the first arg.");

    match mode.as_str() {
        "md2" => {
            let message = collect_message(args);
            let digest = md2_attack::md2_simpler::digest(message);
            digest.iter().for_each(|x| print!("{} ", x));
        },
        "compress" => {},
        "preimage" => {},
        _ => panic!("Mode {} is not recognized.", mode),
    }
}

fn collect_message<I>(blocks: I) -> Vec<u8>
where
    I: Iterator<Item = String>
{
    let mut v = Vec::new();

    for block in blocks{
        v.append(&mut block.split(' ').map(|x| {
            x.parse::<u8>().expect("Incorrect characters in blocks")
        }).collect());
    }

    v
}