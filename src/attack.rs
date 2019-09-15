//! # MD2 preimage attack
//! Finds a message block M_i by given states H_i and H_i+1.
//! The attack is described [here](https://link.springer.com/content/pdf/10.1007%2F978-3-540-30539-2_16.pdf).

use std::sync::Arc;

pub fn get_preimage(s1: &[u8], s2: &[u8]) -> [u8; 16] {
    let A = step1::compute_A(s1, s2, 0u8);

    [0u8; 16]
}

mod step1 {
    use crate::md2;
    use std::sync::Arc;

    type Table = [[u8; 16]; 19];
    type Column = [u8; 19];
    type Row = [u8; 16];

    /// Computes matrix A for the md2 compression function.
    /// # Arguements
    /// - **s1** - H_i state
    /// - **s2** - H_(i+1) state
    /// - **b** - a guessed byte for the 2nd row of the marix
    /// # Returns
    /// A tuple: 1st is the computed A table, 2nd is the last column of C matrix
    pub fn compute_A(s1: &[u8], s2: &[u8], b: u8) -> (Arc<Table>, Arc<Column>) {
        let mut A = [[0u8; 16]; 19];
        // fill in the first and the last rows
        (&mut A[0][..]).copy_from_slice(s1);
        (&mut A[18][..]).copy_from_slice(s2);

        fill_second_row(&mut A);
        fill_lower(&mut A);
        let C = fill_upper(&mut A, b);

        (Arc::new(A), Arc::new(C))
    }

    fn fill_second_row(A: &mut Table) {
        let mut t = 0u8;

        for j in 0..16 {
            A[1][j] = A[0][j] ^ md2::S[t as usize];
            t = A[1][j];
        }
    }

    fn fill_third_row(A: &mut Table, b: u8) {
        let mut t = b;
        for j in 0..16 {
            A[2][j] = A[1][j] ^ md2::S[t as usize];
            t = A[2][j];
        }
    }

    fn fill_lower(A: &mut Table) {
        for i in (3..18).rev() {
            for j in (18 - i)..16 {
                // to form a "lader"
                A[i][j] = A[i + 1][j] ^ md2::S[A[i + 1][j - 1] as usize];
            }
        }
    }

    fn fill_upper(A: &mut Table, b: u8) -> Column {
        let mut C = [0u8; 19];
        C[1] = b;

        fill_third_row(A, b);
        for i in 3..18 {
            for j in (0..(18 - i)).rev() {
                A[i][j] = md2::S_rev[(A[i - 1][j + 1] ^ A[i][j + 1]) as usize];
            }

            C[i - 1] = (md2::S_rev[(A[i][0] ^ A[i - 1][0]) as usize] + (4 - (i as u8 - 2) % 4)) % 4;
        }
        C[17] = (md2::S_rev[(A[18][0] ^ A[18 - 1][0]) as usize]) % 4;

        C
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn get_preimage() {
        let s1 = "0 1 2 3 0 1 2 3 0 1 2 3 0 1 2 3"
            .split(' ')
            .map(|x| x.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();

        let s2 = "0 0 3 2 2 2 1 0 0 0 3 0 3 3 1 2"
            .split(' ')
            .map(|x| x.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();
        let res = "0 0 3 2 2 2 1 0 0 0 3 0 3 3 1 2"
            .split(' ')
            .map(|x| x.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();

        assert_eq!(
            super::get_preimage(s1.as_slice(), s2.as_slice()),
            res.as_slice()
        );
    }

    #[test]
    fn compute_A() {
        let expected_A = [
            [
                1u8, 3u8, 2u8, 2u8, 0u8, 2u8, 1u8, 0u8, 0u8, 3u8, 3u8, 0u8, 1u8, 2u8, 3u8, 0u8,
            ],
            [
                0u8, 2u8, 2u8, 2u8, 0u8, 3u8, 3u8, 2u8, 0u8, 2u8, 3u8, 2u8, 1u8, 1u8, 0u8, 1u8,
            ],
            [
                1u8, 1u8, 1u8, 1u8, 3u8, 1u8, 0u8, 3u8, 2u8, 2u8, 3u8, 0u8, 0u8, 0u8, 1u8, 2u8,
            ],
            [
                2u8, 1u8, 2u8, 1u8, 0u8, 0u8, 1u8, 0u8, 3u8, 0u8, 2u8, 0u8, 1u8, 3u8, 3u8, 0u8,
            ],
            [
                0u8, 0u8, 3u8, 3u8, 2u8, 0u8, 0u8, 1u8, 0u8, 1u8, 1u8, 3u8, 3u8, 1u8, 0u8, 1u8,
            ],
            [
                0u8, 1u8, 0u8, 2u8, 2u8, 0u8, 1u8, 2u8, 0u8, 0u8, 0u8, 2u8, 3u8, 3u8, 2u8, 1u8,
            ],
            [
                0u8, 0u8, 1u8, 1u8, 1u8, 3u8, 3u8, 0u8, 1u8, 3u8, 2u8, 2u8, 3u8, 1u8, 1u8, 2u8,
            ],
            [
                2u8, 0u8, 0u8, 0u8, 0u8, 2u8, 3u8, 2u8, 1u8, 0u8, 3u8, 0u8, 2u8, 1u8, 2u8, 2u8,
            ],
            [
                1u8, 3u8, 2u8, 0u8, 1u8, 1u8, 0u8, 3u8, 3u8, 2u8, 3u8, 2u8, 2u8, 1u8, 1u8, 1u8,
            ],
            [
                0u8, 2u8, 2u8, 0u8, 0u8, 0u8, 1u8, 0u8, 2u8, 2u8, 3u8, 0u8, 3u8, 3u8, 3u8, 3u8,
            ],
            [
                1u8, 1u8, 1u8, 3u8, 2u8, 0u8, 0u8, 1u8, 1u8, 1u8, 0u8, 1u8, 0u8, 2u8, 3u8, 1u8,
            ],
            [
                2u8, 1u8, 2u8, 3u8, 0u8, 1u8, 3u8, 3u8, 3u8, 3u8, 2u8, 1u8, 3u8, 0u8, 2u8, 1u8,
            ],
            [
                0u8, 0u8, 3u8, 1u8, 3u8, 3u8, 1u8, 0u8, 2u8, 3u8, 0u8, 0u8, 2u8, 0u8, 3u8, 3u8,
            ],
            [
                0u8, 1u8, 0u8, 0u8, 2u8, 3u8, 3u8, 2u8, 2u8, 3u8, 2u8, 0u8, 3u8, 2u8, 3u8, 1u8,
            ],
            [
                0u8, 0u8, 1u8, 3u8, 0u8, 2u8, 3u8, 0u8, 3u8, 1u8, 1u8, 3u8, 1u8, 1u8, 0u8, 0u8,
            ],
            [
                2u8, 0u8, 0u8, 2u8, 0u8, 3u8, 1u8, 3u8, 1u8, 2u8, 1u8, 0u8, 0u8, 0u8, 1u8, 3u8,
            ],
            [
                2u8, 0u8, 1u8, 1u8, 3u8, 1u8, 2u8, 3u8, 3u8, 0u8, 0u8, 1u8, 3u8, 2u8, 1u8, 0u8,
            ],
            [
                0u8, 1u8, 2u8, 1u8, 0u8, 0u8, 3u8, 1u8, 0u8, 1u8, 3u8, 3u8, 1u8, 1u8, 2u8, 0u8,
            ],
            [
                3u8, 3u8, 0u8, 0u8, 1u8, 3u8, 1u8, 2u8, 0u8, 0u8, 2u8, 3u8, 3u8, 3u8, 0u8, 1u8,
            ],
        ];

        let expected_C = [
            0u8, 0u8, 0u8, 1u8, 3u8, 2u8, 2u8, 3u8, 1u8, 0u8, 0u8, 1u8, 3u8, 2u8, 2u8, 0u8, 0u8, 1u8,
            0u8,
        ];

        let s1 = "1 3 2 2 0 2 1 0 0 3 3 0 1 2 3 0"
            .split(' ')
            .map(|x| x.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();

        let s2 = "3 3 0 0 1 3 1 2 0 0 2 3 3 3 0 1"
            .split(' ')
            .map(|x| x.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();

        let b = 0;

        let (A, C) = super::step1::compute_A(s1.as_slice(), s2.as_slice(), b);
        let A = *A;
        let C = *C;

        assert_eq!(A, expected_A);
        assert_eq!(C, expected_C);
    }
}
