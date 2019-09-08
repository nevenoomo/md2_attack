//! # MD2 Simpler module
//!
//! MD2 Simpler implements the (md2 algorithm)[https://tools.ietf.org/html/rfc1319], but
//! operating bytes only with values in the interval from 0 up to 3.  

use std::vec::Vec;

static S: [u8; 4] = [1, 3, 0, 2];

/// Calculates a MD2 digest for a given message
pub fn digest(mut m: Vec<u8>) -> [u8; 16] {
    stages::padd(&mut m); // add padding to the message
    stages::add_checksum(&mut m); // add checksum to the message
    let digest = m.chunks(16).fold([0u8; 16], |s, b| stages::process_block(&s, b));

    digest
}

mod stages {
    use std::iter;

    pub fn padd(m: &mut Vec<u8>) {
        // padd the message M with i bytes of value i mod 4 to make N = len(M)
        // to be a multiple of 16
        m.append(
            &mut iter::repeat(m.len() as u8 & 3u8)
                .take(16 - m.len() % 16)
                .collect(),
        );
    }

    pub fn add_checksum(m: &mut Vec<u8>) {
        let mut checksum = [0u8; 16];

        let mut l = 0;

        for i in 0..m.len() / 16 {
            for j in 0..16 {
                let c = m[i * 16 + j] as usize;
                checksum[j] ^= super::S[c ^ l];
                l = checksum[j] as usize;
            }
        }

        m.extend_from_slice(&checksum);
    }

    pub fn process_block(state: &[u8], block: &[u8]) -> [u8; 16]{
        if block.len() != 16 && state.len() != 16 {
            panic!("Incorrect block size.");
        }

        let mut buf = [0u8; 48];
        
        for i in 0..16 {
            buf[i] = state[i];
            buf[i + 16] = block[i];
            buf[i + 32] = buf[i+16]^buf[i];
        }

        let mut t: u8 = 0;
        for i in 0..18 {
            for j in 0..48 {
                buf[j] ^= super::S[t as usize];
                t = buf[j as usize];
            }

            t = t.wrapping_add(i) & 0x3;
        }

        let mut result = [0u8; 16];
        result.copy_from_slice(&buf[..16]);

        result
    }    
}

#[cfg(test)]
mod test {
    #[test]
    fn simple_digest() {
        let message = vec![
            0u8, 3u8, 1u8, 2u8, 1u8, 1u8, 0u8, 2u8, 0u8, 3u8, 3u8, 0u8, 1u8, 1u8, 2u8, 0u8, 3u8,
            2u8, 2u8, 2u8, 2u8, 2u8, 1u8, 0u8, 0u8, 3u8, 3u8, 0u8, 1u8, 2u8, 3u8, 0u8,
        ];
        assert_eq!(
            super::digest(message),
            [1u8, 2u8, 1u8, 2u8, 1u8, 2u8, 3u8, 2u8, 0u8, 3u8, 0u8, 3u8, 0u8, 3u8, 2u8, 3u8]
        );
    }
}
