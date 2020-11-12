//! Moving average convergence divergence
//! An rust implementation for the algorithm presented in https://github.com/woonhulktin/HETSA
//!
//! ## Context
//!
//! This is a computation used in the financial sector to show the relationship between two
//! moving averages of a security's price.  See [0] for more information.
//!
//! Note that this was used to benchmark Veracruz against SEAL and HEAAN homomorphic encryption
//! libraries.
//!
//! [0]: https://www.investopedia.com/terms/m/macd.asp
//!
//! Inputs:                  One.
//! Assumed form of inputs:  a Pinecone-encoded Rust vector of `f64` values.
//! Ensured form of outputs: A Pinecone-encoded Rust vector of `f64` values.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing and
//! copyright information.

use libveracruz::{data_description::write_result, host, return_code};

////////////////////////////////////////////////////////////////////////////////
// Reading inputs.
////////////////////////////////////////////////////////////////////////////////

/// Reads precisely one input, which is assumed to be a Pinecone-encoded vector of `f64`
/// values.
fn read_inputs() -> Result<Vec<f64>, i32> {
    if host::input_count() != 1 {
        return return_code::fail_data_source_count();
    } else {
        let input = host::read_input(0).unwrap();

        match pinecone::from_bytes(&input) {
            Err(_err) => return_code::fail_bad_input(),
            Ok(s) => Ok(s),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// The computation.
////////////////////////////////////////////////////////////////////////////////

fn computation(
    dataset: &[f64],
) -> (
    Vec<f64>,
    Vec<f64>,
    Vec<f64>,
    Vec<f64>,
    Vec<f64>,
    Vec<i32>,
    Vec<f64>,
) {
    let wma12 = wma(dataset, 12);
    let wma26 = wma(dataset, 26);
    // drop the prefix of wma12
    let wma_diff: Vec<f64> = wma12
        .split_at(14)
        .1
        .iter()
        .zip(wma26.iter())
        .map(|(lhs, rhs)| lhs - rhs)
        .collect();

    let wma9 = wma(&wma_diff, 9);

    let macd_wma: Vec<f64> = wma_diff
        // Drop the prefix in wma_diff_iter
        .split_at(9)
        .1
        .iter()
        .zip(wma9.iter())
        .map(|(lhs, rhs)| lhs - rhs)
        .collect();

    let decision_wma = dec(&macd_wma);
    let decisions_wma_approx = dec_approx(&macd_wma, 0.5);

    (
        wma12,
        wma26,
        wma_diff,
        wma9,
        macd_wma,
        decision_wma,
        decisions_wma_approx,
    )
}

fn wma(data: &[f64], window: u32) -> Vec<f64> {
    let weight: Vec<f64> = (0..window)
        .map(|i| (2.0 * (i as f64 + 1.0) / (window as f64 * (window as f64 + 1.0))))
        .collect();

    // The weight vector a window shifts over the data vector,
    // and multiply the data, and sum up.
    data.windows(weight.len())
        .map(|slice| {
            slice
                .iter()
                .zip(weight.iter())
                .fold(0.0, |acc, (lhs, rhs)| acc + (lhs * rhs))
        })
        .collect()
}

fn dec(data: &[f64]) -> Vec<i32> {
    data.windows(2)
        .map(|w| {
            match w {
                [first, second] => {
                    // flip_relu
                    let mul = first * second;
                    let dec_point: f64 = if mul.abs() < f64::EPSILON || mul.is_sign_positive() {
                        0.0
                    } else {
                        //  mul.is_sign_negative()
                        -1.0
                    };
                    // decision
                    let decision = dec_point * (first - second);
                    if decision.abs() < f64::EPSILON {
                        0
                    } else if decision.is_sign_negative() {
                        -1
                    } else {
                        // is_sign_positive
                        1
                    }
                }
                _otherwise => unreachable!(),
            }
        })
        .collect()
}

fn dec_approx(data: &[f64], norm: f64) -> Vec<f64> {
    data.windows(2)
        .map(|w| match w {
            [first, second] => {
                let mt_first = norm * first;
                let mt_second = norm * second;
                let rst = mt_first * mt_second;
                let rst = -0.0001 * (rst.powi(9)) + 0.0003 * (rst.powi(8)) + 0.0025 * (rst.powi(7))
                    - 0.009 * (rst.powi(6))
                    - 0.0253 * (rst.powi(5))
                    + 0.0984 * (rst.powi(4))
                    + 0.0882 * (rst.powi(3))
                    - 0.5173 * (rst.powi(2))
                    + 0.4475 * rst
                    - 0.0753;
                rst * (mt_first - mt_second)
            }
            _otherwise => unreachable!(),
        })
        .collect()
}

/// Entry point: reads the vector of floats, processes them, and writes back a new vector of
/// floats as output.
fn main() -> return_code::Veracruz {
    let dataset = read_inputs()?;
    let (_wma12, _wma26, _wma_diff, _wma9, _macd_wma, _decision_wma, decisions_wma_approx) =
        computation(dataset.as_slice());
    write_result::<Vec<f64>>(decisions_wma_approx)
}
