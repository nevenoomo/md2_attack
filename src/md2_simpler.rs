//! # MD2 Simpler module
//!
//! MD2 Simpler implements the (md2 algorithm)[https://tools.ietf.org/html/rfc1319], but
//! operating bytes only with values in the interval from 0 up to 3.  

use std::vec::Vec;

static S: [u8; 4] = [1, 3, 0, 2];

/// Calculates a MD2 digest for a given message
pub fn digest(mut m: Vec<u8>) -> [u8; 16] {
    let mut digest_buffer = [0u8; 48];

    stages::padd(&mut m); // add padding to the message
    stages::add_checksum(&mut m); // add checksum to the message
    stages::process_message(&m, &mut digest_buffer); // process message in blocks
    let mut digest: [u8; 16] = [0u8; 16];
    digest.copy_from_slice(&digest_buffer[..16]);

    digest
}

mod stages {
    use std::iter;

    pub fn padd(m: &mut Vec<u8>) {
        // padd the message M with i bytes of value i mod 4 to make N = len(M)
        // to be a multiple of 16
        m.append(
            &mut iter::repeat(m.len() as u8 % 4)
                .take(16 - m.len() % 16)
                .collect(),
        ); // IDEA try &mut &[m.len() as u8 % 4].repeat(16 - m.len() % 16)
    }

    pub fn add_checksum(m: &mut Vec<u8>) {
        let mut checksum = [0u8; 16];

        let mut l = 0;

        for i in 0..m.len() / 16 {
            for j in 0..16 {
                let c = m[i * 16 + j] as usize;
                checksum[j] = super::S[c ^ l];
                l = checksum[j] as usize;
            }
        }

        m.extend_from_slice(&checksum);
    }

    pub fn process_message(m: &Vec<u8>, buf: &mut [u8; 48]) {
        for i in 0..m.len() / 16 {
            for j in 0..16 {
                buf[16 + j] = m[i * 16 + j];
                buf[32 + j] = buf[16 + j] ^ buf[j];
            }

            let mut t = 0u8;

            for j in 0..18 {
                for k in 0..48 {
                    t = buf[k] ^ super::S[t as usize];
                    buf[k] = t;
                }

                t = t.overflowing_add(j).0 & 3u8; // take least two bits
            }
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn digest() {
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
