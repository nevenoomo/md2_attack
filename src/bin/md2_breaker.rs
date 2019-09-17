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
use std::iter::Iterator;
use std::string::String;
use std::vec::Vec;

fn main() {
    let mut args = env::args().skip(1); // skipping the name of the program
    let mode = args.next().expect("Mode expected as the first arg.");
    let result;

    match mode.as_str() {
        "md2" => {
            let message = collect_message(args);
            result = md2_attack::md2::digest(message);
        }
        "compress" => {
            let state = collect_block(args.next().expect("A state block H expected"));
            let message = collect_block(args.next().expect("A message block M expected"));

            result = md2_attack::md2::compress(&state, &message);
        }
        "preimage" => {
            let state1 = collect_block(args.next().expect("A state block H_i expected"));
            let state2 = collect_block(args.next().expect("A state block H_i expected"));

            result = md2_attack::attack::get_preimage(&state1, &state2);
        }
        _ => panic!("Mode {} is not recognized.", mode),
    }

    result.iter().for_each(|x| print!("{} ", x));
    println!();
}

fn collect_message<I>(blocks: I) -> Vec<u8>
where
    I: Iterator<Item = String>,
{
    let mut v = Vec::new();

    for block in blocks {
        v.append(&mut collect_block(block));
    }

    v
}

fn collect_block(block: String) -> Vec<u8> {
    block
        .split(' ')
        .map(|x| x.parse::<u8>().expect("Incorrect characters in blocks"))
        .collect()
}
