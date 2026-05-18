//@run:1
//This is a direct copy of the test `smoke_test` from `klu-rs` at 0.4.0.
use klu_rs::*;
use std::rc::Rc;

#[derive(Debug)]
struct LinearSystem<D> {
    matrix_shape: Vec<Vec<i32>>,
    matrix_data: Vec<D>,
    matrix_len: u32,
    rhs: Vec<D>,
}

impl<D: KluData> LinearSystem<D> {
    fn gen_klu_spec(&self) -> Rc<KluMatrixSpec<i32>> {
        let dim = self.rhs.len() as i32;
        let mut builder = KluMatrixBuilder::new(dim as i32);
        self.for_matirx_entry(0, |col, row, _| builder.add_entry(col, row));
        builder.finish(KluSettings::new())
    }

    fn data(&self, matrix: u32) -> &[D] {
        let start = self.matrix_len * matrix;
        let end = self.matrix_len * (matrix + 1);
        &self.matrix_data[start as usize..end as usize]
    }

    fn for_matirx_entry(&self, matrix: u32, mut f: impl FnMut(i32, i32, D)) {
        let mut i = 0;
        let data = self.data(matrix);
        for (col, col_data) in self.matrix_shape.iter().enumerate() {
            for &row in col_data {
                f(col as i32, row, data[i]);
                i += 1;
            }
        }
    }

    fn test_klu(&self) {
        let spec = self.gen_klu_spec();
        let mut matrix = spec.create_matrix().expect("matrix is not empty");
        let num_matricies = self.matrix_data.len() as u32 / self.matrix_len;
        for i in 0..num_matricies {
            self.test_klu_solve(i as u32, &mut matrix);
        }
    }

    fn test_klu_solve(
        &self,
        matrix: u32,
        dst: &mut FixedKluMatrix<i32, D>,
    ) {
        self.for_matirx_entry(matrix, |col, row, val| {
            dst[(col, row)].set(val);
        });
        let is_singluar = dst.lu_factorize(Some(1e-12));
        if is_singluar {
            // singular matrix... assume this is correct
            return;
        }
        let mut solv = self.rhs.clone();
        dst.solve_linear_system(&mut solv);
        let mut check = vec![D::zero(); solv.len()];

        self.for_matirx_entry(matrix, |col, row, val| {
            check[row as usize] += val * solv[col as usize]
        });
    }
}

fn main() {
   LinearSystem {
        matrix_shape: vec![vec![0], vec![1]],
        matrix_data: vec![314.2, 5.1],
        matrix_len: 2,
        rhs: vec![314.2, 10.2],
    }
    .test_klu();
}