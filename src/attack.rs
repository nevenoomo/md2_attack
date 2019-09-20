//! # MD2 preimage attack
//! Finds a message block M_i by given states H_i and H_i+1.
//! The attack is described [here](https://link.springer.com/content/pdf/10.1007%2F978-3-540-30539-2_16.pdf).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::thread;

type Matrix = [[u8; 16]; 19];
type Column = [u8; 19];
type Row = [u8; 16];
type HalfMessage = [u8; 8];
type MessageTable = (Vec<HalfMessage>, Vec<HalfMessage>);
type Table = HashMap<step2::Cortege, MessageTable>;

enum CtlMessage<T> {
    Terminate,
    Finished,
    Res(T),
}

pub fn get_preimage(s_init: &[u8], s_final: &[u8]) -> [u8; 16] {
    for i in 0..4u8 {
        let mut s1 = [0u8; 16];
        let mut s2 = [0u8; 16];
        s1.copy_from_slice(s_init);
        s2.copy_from_slice(s_final);
        if let Some(res) = do_calculations(i, s1, s2) {
            return res;
        }
    }

    panic!("No message found");
}

fn do_calculations(a: u8, s1: Row, s2: Row) -> Option<Row> {
    let (a_mat, c_col) = step1::compute_matrix_a(&s1, &s2, a);

    //UGLY use iterator instead
    for b0 in 0..4u8 {
        for b1 in 0..4u8 {
            for b2 in 0..4u8 {
                for b3 in 0..4u8 {
                    let t = Arc::new(RwLock::new(Table::new()));
                    let b_guess = [b3, b2, b1, b0];

                    fill_tables(t.clone(), a_mat.clone(), c_col.clone(), b_guess);

                    if let Some(res) = step2::get_correct_message(t.clone(), &s1, &s2) {
                        return Some(res);
                    }
                }
            }
        }
    }

    None
}

fn fill_tables(t: Arc<RwLock<Table>>, a_mat: Arc<Matrix>, c_col: Arc<Column>, b_guess: [u8; 4]) {
    let t1 = t.clone();
    let t2 = t.clone();
    let a1_mat = a_mat.clone();
    let a2_mat = a_mat.clone();
    let c_column = c_col.clone();

    let hnd_table1 = thread::spawn(move || {
        step2::fill_t1(t1, &b_guess, a1_mat);
    });

    let hnd_table2 = thread::spawn(move || {
        step2::fill_t2(t2, &b_guess, a2_mat, c_column);
    });

    hnd_table1.join().expect("Error while filling tables");
    hnd_table2.join().expect("Error while filling tables");
}

mod step1 {
    use super::*;
    use crate::md2;
    use std::sync::Arc;

    /// Computes matrix A for the md2 compression function.
    /// # Arguements
    /// - **s1** - H_i state
    /// - **s2** - H_(i+1) state
    /// - **b** - a guessed byte for the 2nd row of the marix
    /// # Returns
    /// A tuple: 1st is the computed A Matrix, 2nd is the last column of C matrix
    pub fn compute_matrix_a(s1: &[u8], s2: &[u8], b: u8) -> (Arc<Matrix>, Arc<Column>) {
        let mut a_mat = [[0u8; 16]; 19];
        // fill in the first and the last rows
        (&mut a_mat[0][..]).copy_from_slice(s1);
        (&mut a_mat[18][..]).copy_from_slice(s2);

        fill_second_row(&mut a_mat);
        fill_lower(&mut a_mat);
        let c_col = fill_upper(&mut a_mat, b);

        (Arc::new(a_mat), Arc::new(c_col))
    }

    fn fill_second_row(a_mat: &mut Matrix) {
        let mut t = 0u8;

        for j in 0..16 {
            a_mat[1][j] = a_mat[0][j] ^ md2::S[t as usize];
            t = a_mat[1][j];
        }
    }

    fn fill_third_row(a_mat: &mut Matrix, b: u8) {
        let mut t = b;
        for j in 0..16 {
            a_mat[2][j] = a_mat[1][j] ^ md2::S[t as usize];
            t = a_mat[2][j];
        }
    }

    fn fill_lower(a_mat: &mut Matrix) {
        for i in (3..18).rev() {
            for j in (18 - i)..16 {
                // to form a "lader"
                a_mat[i][j] = a_mat[i + 1][j] ^ md2::S[a_mat[i + 1][j - 1] as usize];
            }
        }
    }

    fn fill_upper(a_mat: &mut Matrix, b: u8) -> Column {
        let mut c_col = [0u8; 19];
        c_col[1] = b;

        fill_third_row(a_mat, b);
        for i in 3..18 {
            for j in (0..(18 - i)).rev() {
                a_mat[i][j] = md2::S_REV[(a_mat[i - 1][j + 1] ^ a_mat[i][j + 1]) as usize];
            }

            c_col[i - 1] = (md2::S_REV[(a_mat[i][0] ^ a_mat[i - 1][0]) as usize]
                + (4 - (i as u8 - 2) % 4))
                % 4;
        }
        c_col[17] = (md2::S_REV[(a_mat[18][0] ^ a_mat[18 - 1][0]) as usize]) % 4;

        c_col
    }
}

mod step2 {
    use super::*;
    use crate::md2;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex, RwLock};

    type HalfMessage = [u8; 8];
    type PartB = [u8; 4];
    type PartC = [u8; 4];

    #[derive(PartialEq, Hash, Eq, Debug)]
    pub struct Cortege {
        b: PartB,
        c: PartC,
    }

    struct ArrayValsIterator {
        _m: HalfMessage,
        _overflow: bool,
    }

    impl ArrayValsIterator {
        fn new(m: HalfMessage) -> ArrayValsIterator {
            ArrayValsIterator {
                _m: m,
                _overflow: false,
            }
        }
    }

    impl Iterator for ArrayValsIterator {
        type Item = HalfMessage;

        fn next(&mut self) -> Option<Self::Item> {
            if self._overflow {
                return None;
            }

            let mut c = 0;
            let mut a = 1;
            let res = self._m;

            for v in self._m.iter_mut() {
                *v += c + a;
                a = 0;
                c = *v / 4;
                *v %= 4;
            }

            if c != 0 {
                self._overflow = true;
            }

            Some(res)
        }
    }

    pub fn get_correct_message(
        t: Arc<RwLock<Table>>,
        s_init: &[u8],
        s_final: &[u8],
    ) -> Option<[u8; 16]> {
        const NUM_OF_THREADS: usize = 5;

        let (send_fin, recv_fin) = mpsc::channel::<CtlMessage<Row>>();
        let (send_term, recv_term) = mpsc::channel::<CtlMessage<Row>>();
        let recv_term = Arc::new(Mutex::new(recv_term));

        let mut children = Vec::new();
        let tab = t.read().expect("Concurrency error");
        let task_size = tab.keys().len() / NUM_OF_THREADS;

        for i in 0..NUM_OF_THREADS {
            let tab = t.clone();
            let sf = send_fin.clone();
            let rt = recv_term.clone();
            let mut st1: Row = [0u8; 16];
            st1.copy_from_slice(s_init);
            let mut st2: Row = [0u8; 16];
            st2.copy_from_slice(s_final);

            children.push(thread::spawn(move || {
                let mut m = [0u8; 16];
                let tab = tab.read().expect("Concurrency error");
                let st1 = st1;
                let st2 = st2;
                let to_process = if i == NUM_OF_THREADS - 1 {
                    tab.len() - i * task_size
                } else {
                    task_size
                };

                for (v1, v2) in tab.values().skip(task_size * i).take(to_process) {
                    if v1.len() == 0 || v2.len() == 0 {
                        continue;
                    }
                    for m1 in v1 {
                        for m2 in v2 {
                            &m[..8].copy_from_slice(m1);
                            &m[8..].copy_from_slice(m2);

                            if md2::compress(&st1, &m) == st2 {
                                // Send result to the main thread
                                sf.send(CtlMessage::<Row>::Res(m)).expect("Broken channel");
                                return;
                            }
                        }
                        // Maybe it is time to finish
                        let r = rt.lock().expect("Mutex lock error").try_recv();

                        match r {
                            Ok(CtlMessage::<Row>::Terminate) => return,
                            _ => continue,
                        }
                    }
                }

                sf.send(CtlMessage::<Row>::Finished)
                    .expect("Concurrency error");
            }));
        }

        let mut cnt = 0;
        loop {
            let r = recv_fin.try_recv();

            match r {
                Ok(CtlMessage::<Row>::Res(result)) => {
                    for _ in children.iter() {
                        send_term
                            .send(CtlMessage::<Row>::Terminate)
                            .expect("Broken channel");
                    }
                    for hdl in children.into_iter() {
                        hdl.join().expect("Concurrency error");
                    }

                    return Some(result);
                }
                Ok(CtlMessage::<Row>::Finished) => {
                    cnt += 1;
                    if cnt == NUM_OF_THREADS {
                        return None;
                    }
                }
                _ => continue,
            }
        }
    }

    pub fn fill_t1(t: Arc<RwLock<Table>>, b_guess: &PartB, a_mat: Arc<Matrix>) {
        for m1 in ArrayValsIterator::new([0u8; 8]) {
            let c_upper = a_mat[0][..8]
                .iter()
                .zip(m1.iter())
                .map(|(x, y)| x ^ y)
                .collect::<Vec<u8>>(); // c_upper - top part of matrix C

            let cortege = Cortege {
                b: compute_b_left(&m1, a_mat.clone()),
                c: compute_c_left(c_upper.as_slice(), b_guess),
            };

            let mut tab = t.write().expect("Concurrency error");

            if tab.contains_key(&cortege) {
                tab.get_mut(&cortege).unwrap().0.push(m1); // push a message to the corresponding value
            } else {
                tab.insert(cortege, (vec![m1], vec![]));
            }
        }
    }

    pub fn fill_t2(t: Arc<RwLock<Table>>, b_guess: &PartB, a_mat: Arc<Matrix>, c_col: Arc<Column>) {
        for m2 in ArrayValsIterator::new([0u8; 8]) {
            let c_upper = a_mat[0][8..]
                .iter()
                .zip(m2.iter())
                .map(|(x, y)| x ^ y)
                .collect::<Vec<u8>>(); // c_upper - top part of matrix C

            let cortege = Cortege {
                b: compute_b_right(&m2, b_guess),
                c: compute_c_right(c_upper.as_slice(), c_col.clone()),
            };

            let mut tab = t.write().expect("Concurrency error");

            if tab.contains_key(&cortege) {
                tab.get_mut(&cortege).unwrap().1.push(m2); // push a message to the corresponding value
            } else {
                tab.insert(cortege, (vec![], vec![m2]));
            }
        }
    }

    fn compute_b_left(m: &HalfMessage, a_mat: Arc<Matrix>) -> PartB {
        //UGLY pass only part of A
        let mut b = [a_mat[1][15], a_mat[2][15], a_mat[3][15], a_mat[4][15]];

        for i in 0..8 {
            b[0] = m[i] ^ md2::S[b[0] as usize];
            b[1] = b[0] ^ md2::S[b[1] as usize];
            b[2] = b[1] ^ md2::S[b[2] as usize];
            b[3] = b[2] ^ md2::S[b[3] as usize];
        }

        b
    }

    fn compute_c_left(c_upper: &[u8], b_guess: &PartB) -> PartC {
        let mut c = *b_guess;

        for i in 0..8 {
            c[0] = c_upper[i] ^ md2::S[c[0] as usize];
            c[1] = c[0] ^ md2::S[c[1] as usize];
            c[2] = c[1] ^ md2::S[c[2] as usize];
            c[3] = c[2] ^ md2::S[c[3] as usize];
        }

        c
    }

    fn compute_b_right(m: &HalfMessage, b_guess: &PartB) -> PartB {
        let mut b = *b_guess;

        for i in (0..8).rev() {
            b[3] = md2::S_REV[(b[2] ^ b[3]) as usize];
            b[2] = md2::S_REV[(b[1] ^ b[2]) as usize];
            b[1] = md2::S_REV[(b[0] ^ b[1]) as usize];
            b[0] = md2::S_REV[(m[i] ^ b[0]) as usize];
        }

        b
    }

    fn compute_c_right(c_upper: &[u8], c_col: Arc<Column>) -> PartB {
        let mut c = [0u8; 4];
        c.copy_from_slice(&c_col[1..5]);

        for i in (0..8).rev() {
            c[3] = md2::S_REV[(c[2] ^ c[3]) as usize];
            c[2] = md2::S_REV[(c[1] ^ c[2]) as usize];
            c[1] = md2::S_REV[(c[0] ^ c[1]) as usize];
            c[0] = md2::S_REV[(c_upper[i] ^ c[0]) as usize];
        }

        c
    }

    #[cfg(test)]
    mod test {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::sync::Arc;

        #[test]
        fn message_iteration() {
            let mut m = super::ArrayValsIterator::new([0u8; 8]);

            assert_eq!(m.next(), Some([0u8; 8]));
            assert_eq!(m.next(), Some([1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]));
        }

        #[test]
        fn eq() {
            let c1 = super::Cortege {
                b: [0u8; 4],
                c: [0u8; 4],
            };
            let c2 = super::Cortege {
                b: [0u8; 4],
                c: [0u8; 4],
            };

            assert!(c1 == c2);
        }

        #[test]
        fn hash() {
            let c1 = super::Cortege {
                b: [0u8; 4],
                c: [0u8; 4],
            };
            let c2 = super::Cortege {
                b: [0u8; 4],
                c: [0u8; 4],
            };

            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();

            c1.hash(&mut h1);
            c2.hash(&mut h2);

            assert_eq!(h1.finish(), h2.finish());
        }

        #[test]
        fn b_and_c_computation() {
            let s1 = "1 3 2 2 0 2 1 0 0 3 3 0 1 2 3 0"
                .split(' ')
                .map(|x| x.parse::<u8>().unwrap())
                .collect::<Vec<u8>>();

            let m = "1 2 0 2 3 1 0 2 0 3 3 0 1 1 2 0"
                .split(' ')
                .map(|x| x.parse::<u8>().unwrap())
                .collect::<Vec<u8>>();

            let c_upper: Vec<u8> = s1.iter().zip(m.iter()).map(|(x, y)| x ^ y).collect();
            let a_mat = [
                [1, 3, 2, 2, 0, 2, 1, 0, 0, 3, 3, 0, 1, 2, 3, 0],
                [0, 2, 2, 2, 0, 3, 3, 2, 0, 2, 3, 2, 1, 1, 0, 1],
                [1, 1, 1, 1, 3, 1, 0, 3, 2, 2, 3, 0, 0, 0, 1, 2],
                [2, 1, 2, 1, 0, 0, 1, 0, 3, 0, 2, 0, 1, 3, 3, 0],
                [0, 0, 3, 3, 2, 0, 0, 1, 0, 1, 1, 3, 3, 1, 0, 1],
                [0, 1, 0, 2, 2, 0, 1, 2, 0, 0, 0, 2, 3, 3, 2, 1],
                [0, 0, 1, 1, 1, 3, 3, 0, 1, 3, 2, 2, 3, 1, 1, 2],
                [2, 0, 0, 0, 0, 2, 3, 2, 1, 0, 3, 0, 2, 1, 2, 2],
                [1, 3, 2, 0, 1, 1, 0, 3, 3, 2, 3, 2, 2, 1, 1, 1],
                [0, 2, 2, 0, 0, 0, 1, 0, 2, 2, 3, 0, 3, 3, 3, 3],
                [1, 1, 1, 3, 2, 0, 0, 1, 1, 1, 0, 1, 0, 2, 3, 1],
                [2, 1, 2, 3, 0, 1, 3, 3, 3, 3, 2, 1, 3, 0, 2, 1],
                [0, 0, 3, 1, 3, 3, 1, 0, 2, 3, 0, 0, 2, 0, 3, 3],
                [0, 1, 0, 0, 2, 3, 3, 2, 2, 3, 2, 0, 3, 2, 3, 1],
                [0, 0, 1, 3, 0, 2, 3, 0, 3, 1, 1, 3, 1, 1, 0, 0],
                [2, 0, 0, 2, 0, 3, 1, 3, 1, 2, 1, 0, 0, 0, 1, 3],
                [2, 0, 1, 1, 3, 1, 2, 3, 3, 0, 0, 1, 3, 2, 1, 0],
                [0, 1, 2, 1, 0, 0, 3, 1, 0, 1, 3, 3, 1, 1, 2, 0],
                [3, 3, 0, 0, 1, 3, 1, 2, 0, 0, 2, 3, 3, 3, 0, 1],
            ];
            let b_mat = [
                [1, 2, 0, 2, 3, 1, 0, 2, 0, 3, 3, 0, 1, 1, 2, 0],
                [2, 2, 0, 3, 1, 2, 0, 3, 2, 3, 1, 3, 3, 3, 0, 1],
                [2, 2, 0, 2, 1, 1, 3, 1, 1, 0, 0, 2, 3, 1, 3, 3],
                [3, 0, 1, 1, 2, 1, 0, 0, 0, 1, 3, 0, 2, 1, 0, 2],
                [0, 1, 2, 1, 1, 2, 0, 1, 3, 3, 1, 3, 0, 0, 1, 1],
                [3, 3, 0, 0, 0, 3, 2, 1, 0, 2, 1, 0, 1, 3, 3, 3],
                [3, 1, 3, 2, 0, 2, 2, 1, 3, 0, 0, 1, 2, 3, 1, 0],
                [3, 3, 1, 1, 3, 0, 3, 3, 1, 3, 2, 1, 1, 0, 0, 1],
                [0, 2, 1, 2, 3, 2, 3, 1, 2, 3, 0, 0, 0, 1, 3, 3],
                [2, 2, 1, 1, 0, 3, 1, 2, 2, 3, 2, 0, 1, 2, 3, 1],
                [1, 1, 2, 1, 3, 1, 2, 2, 2, 3, 0, 1, 2, 2, 3, 3],
                [2, 1, 1, 2, 3, 3, 0, 3, 0, 2, 0, 0, 3, 0, 2, 3],
                [0, 0, 0, 3, 1, 0, 1, 0, 1, 1, 3, 2, 3, 2, 2, 3],
                [3, 2, 0, 2, 1, 3, 3, 2, 1, 2, 3, 0, 2, 2, 2, 3],
                [2, 2, 0, 3, 3, 1, 0, 3, 3, 0, 2, 0, 3, 0, 3, 1],
                [0, 3, 2, 3, 1, 2, 0, 2, 3, 2, 2, 0, 2, 0, 2, 1],
                [1, 0, 3, 1, 2, 2, 0, 3, 1, 1, 1, 3, 0, 1, 1, 2],
                [0, 1, 0, 0, 3, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 3],
                [3, 3, 2, 0, 2, 0, 0, 1, 3, 2, 0, 3, 2, 0, 1, 0],
            ];
            let c_mat = [
                [0, 1, 2, 0, 3, 3, 1, 2, 0, 0, 0, 0, 0, 3, 1, 0],
                [3, 3, 0, 1, 0, 2, 1, 1, 3, 2, 0, 1, 3, 1, 2, 0],
                [1, 0, 1, 2, 0, 3, 3, 3, 1, 1, 3, 3, 1, 2, 2, 0],
                [1, 3, 3, 0, 1, 0, 2, 3, 3, 3, 1, 0, 0, 3, 0, 1],
                [2, 3, 1, 3, 3, 2, 2, 3, 1, 0, 0, 1, 3, 1, 3, 3],
                [0, 2, 1, 0, 2, 2, 2, 3, 3, 2, 0, 0, 2, 1, 0, 2],
                [1, 1, 2, 0, 3, 0, 3, 1, 0, 3, 2, 0, 3, 3, 2, 2],
                [2, 1, 1, 3, 1, 3, 1, 2, 0, 2, 2, 0, 2, 3, 0, 3],
                [0, 0, 0, 2, 1, 0, 0, 3, 2, 2, 2, 0, 3, 1, 3, 1],
                [3, 2, 0, 3, 3, 2, 0, 2, 2, 2, 2, 0, 2, 1, 0, 0],
                [1, 1, 3, 1, 0, 3, 2, 2, 2, 2, 2, 0, 3, 3, 2, 0],
                [3, 3, 1, 2, 0, 2, 2, 2, 2, 2, 2, 0, 2, 3, 0, 1],
                [1, 0, 0, 3, 2, 2, 2, 2, 2, 2, 2, 0, 3, 1, 3, 3],
                [3, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 1, 0, 2],
                [0, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 3, 3, 2, 2],
                [3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 0, 3, 0],
                [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 2, 0, 2, 0],
                [1, 0, 2, 3, 1, 0, 2, 3, 1, 0, 2, 1, 1, 3, 0, 1],
                [0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 2, 1, 0, 1, 2],
            ];

            let mut b_expected = [0u8; 4];
            let mut c_expected = [0u8; 4];
            for i in 0..4 {
                b_expected[i] = b_mat[i + 1][7];
                c_expected[i] = c_mat[i + 1][7];
            }

            let mut m1 = [0u8; 8];
            let mut m2 = [0u8; 8];
            let mut c1 = [0u8; 8];
            let mut c2 = [0u8; 8];
            let mut c_column = [0u8; 19];
            let b_guess = [1, 3, 2, 1];

            m1.copy_from_slice(&m[..8]);
            m2.copy_from_slice(&m[8..]);
            c1.copy_from_slice(&c_upper[..8]);
            c2.copy_from_slice(&c_upper[8..]);

            for i in 0..19 {
                c_column[i] = c_mat[i][15];
            }

            assert_eq!(super::compute_b_left(&m1, Arc::new(a_mat)), b_expected);
            assert_eq!(super::compute_c_left(&c1, &b_guess), c_expected);
            assert_eq!(super::compute_b_right(&m2, &b_guess), b_expected);
            assert_eq!(super::compute_c_right(&c2, Arc::new(c_column)), c_expected);
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, RwLock};

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

        let preimage = super::get_preimage(s1.as_slice(), s2.as_slice());
        println!("{:?}", preimage);

        if crate::md2::compress(&s1, &preimage) != s2.as_slice() {
            panic!("Not preimage");
        }
    }

    #[test]
    fn get_preimage_with_known_params() {
        let s1 = "1 3 2 2 0 2 1 0 0 3 3 0 1 2 3 0"
            .split(' ')
            .map(|x| x.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();

        let s2 = "3 3 0 0 1 3 1 2 0 0 2 3 3 3 0 1"
            .split(' ')
            .map(|x| x.parse::<u8>().unwrap())
            .collect::<Vec<u8>>();

        let b_guess = [1, 3, 2, 1];
        let a_mat = [
            [1, 3, 2, 2, 0, 2, 1, 0, 0, 3, 3, 0, 1, 2, 3, 0],
            [0, 2, 2, 2, 0, 3, 3, 2, 0, 2, 3, 2, 1, 1, 0, 1],
            [1, 1, 1, 1, 3, 1, 0, 3, 2, 2, 3, 0, 0, 0, 1, 2],
            [2, 1, 2, 1, 0, 0, 1, 0, 3, 0, 2, 0, 1, 3, 3, 0],
            [0, 0, 3, 3, 2, 0, 0, 1, 0, 1, 1, 3, 3, 1, 0, 1],
            [0, 1, 0, 2, 2, 0, 1, 2, 0, 0, 0, 2, 3, 3, 2, 1],
            [0, 0, 1, 1, 1, 3, 3, 0, 1, 3, 2, 2, 3, 1, 1, 2],
            [2, 0, 0, 0, 0, 2, 3, 2, 1, 0, 3, 0, 2, 1, 2, 2],
            [1, 3, 2, 0, 1, 1, 0, 3, 3, 2, 3, 2, 2, 1, 1, 1],
            [0, 2, 2, 0, 0, 0, 1, 0, 2, 2, 3, 0, 3, 3, 3, 3],
            [1, 1, 1, 3, 2, 0, 0, 1, 1, 1, 0, 1, 0, 2, 3, 1],
            [2, 1, 2, 3, 0, 1, 3, 3, 3, 3, 2, 1, 3, 0, 2, 1],
            [0, 0, 3, 1, 3, 3, 1, 0, 2, 3, 0, 0, 2, 0, 3, 3],
            [0, 1, 0, 0, 2, 3, 3, 2, 2, 3, 2, 0, 3, 2, 3, 1],
            [0, 0, 1, 3, 0, 2, 3, 0, 3, 1, 1, 3, 1, 1, 0, 0],
            [2, 0, 0, 2, 0, 3, 1, 3, 1, 2, 1, 0, 0, 0, 1, 3],
            [2, 0, 1, 1, 3, 1, 2, 3, 3, 0, 0, 1, 3, 2, 1, 0],
            [0, 1, 2, 1, 0, 0, 3, 1, 0, 1, 3, 3, 1, 1, 2, 0],
            [3, 3, 0, 0, 1, 3, 1, 2, 0, 0, 2, 3, 3, 3, 0, 1],
        ];
        let a_mat = Arc::new(a_mat);
        let c_col = [0, 0, 0, 1, 3, 2, 2, 3, 1, 0, 0, 1, 3, 2, 2, 0, 0, 1, 2];
        let c_col = Arc::new(c_col);

        let t = Arc::new(RwLock::new(super::Table::new()));
        super::fill_tables(t.clone(), a_mat.clone(), c_col.clone(), b_guess);

        match super::step2::get_correct_message(t.clone(), &s1, &s2) {
            Some(_) => return,
            _ => panic!(""),
        }
    }

    #[test]
    fn compute_matrix_a() {
        let expected_a = [
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

        let expected_c = [
            0u8, 0u8, 0u8, 1u8, 3u8, 2u8, 2u8, 3u8, 1u8, 0u8, 0u8, 1u8, 3u8, 2u8, 2u8, 0u8, 0u8,
            1u8, 0u8,
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

        let (a_mat, c_col) = super::step1::compute_matrix_a(s1.as_slice(), s2.as_slice(), b);
        let a_mat = *a_mat;
        let c_col = *c_col;

        assert_eq!(a_mat, expected_a);
        assert_eq!(c_col, expected_c);
    }
}
