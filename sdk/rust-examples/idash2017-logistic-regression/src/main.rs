//! Logistic regression example
//! A Rust implementaion of the logistic regression algorithm presented in https://github.com/kimandrik/IDASH2017
//!
//! ## Context
//!
//! A number of competing supermarkets want to collectively pool some of their data on
//! customer preferences to be able to better compete against their larger competitors.  However,
//! as each individual supermarket does not trust any other supermarket in the computation, each
//! would like to keep their respective datasets private, lest one of their competitors use it to
//! lure customers their way.  The supermarkets do agree, however, that a logistic regression model
//! should be learnt over the combined datasets, and made available to all.  Other than that, no
//! supermarket wants to reveal anything about their data to any other.
//!
//! Note that this algorithm is a direct port of a logistic regression implementation submitted
//! to the IDASH 2017 competition, which was originally written in C++.  We've rewritten this in
//! Rust to compare the performance of Veracruz against various versions of this original code.
//!
//! Inputs:                  An arbitrary number.
//! Assumed form of inputs:  an arbitrary number of Pinecone-encoded Rust `Dataset` structs (see
//!                          below).
//! Ensured form of outputs: A Pinecone-encoded Rust vector of `f64` values describing the parameters
//!                          of the learnt logistic regression model.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::anyhow;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

////////////////////////////////////////////////////////////////////////////////
// Reading input
////////////////////////////////////////////////////////////////////////////////

/// The type of input datasets: a table of 64-bit floating point values.
type Dataset = Vec<Vec<f64>>;

/// Reads the input `(training_set, test_set, number_of_iteration, degree_of_sigmoid, gamma_up,
/// gamma_down)`.  Returns the following error codes:
///
///   - [`return_code::ErrorCode::BadInput`] if the strings are not encoded in Pinecone and
///     therefore cannot be decoded,
///   - [`return_code::ErrorCode::DataSourceCount`] if the number of inputs provided to the
///     program is not exactly 1.
///
fn read_inputs<T: AsRef<Path>>(path: T) -> anyhow::Result<(Dataset, Dataset, u64, u64, i64, i64)> {
    let input = fs::read(path.as_ref())?;
    Ok(pinecone::from_bytes(&input)?)
}

////////////////////////////////////////////////////////////////////////////////
// The computation.
////////////////////////////////////////////////////////////////////////////////

/// Entry point of the actual computation.
fn nlgd(
    train_set: &mut Dataset,
    test_set: &mut Dataset,
    num_of_iter: u64,
    degree_of_sigmoid: u64,
    gamma_up: i64,
    gamma_down: i64,
) -> anyhow::Result<(Vec<f64>, f64, f64)> {
    let training_sample = train_set.len();

    normalize_data_inplace(train_set)?;
    normalize_data_inplace(test_set)?;

    let mut w_data = vec![0.0 as f64; get_factor_len(&train_set)?];
    let mut v_data = vec![0.0 as f64; get_factor_len(&train_set)?];

    let mut alpha0: f64 = 0.01;
    let mut alpha1: f64 = (1.0 + (1.0 + 4.0 * alpha0 * alpha0).sqrt()) / 2.0;

    for iter in 0..num_of_iter {
        let eta = (1.0 - alpha0) / alpha1;
        let gamma = if gamma_down > 0 {
            gamma_up as f64 / gamma_down as f64 / training_sample as f64
        } else {
            gamma_up as f64 / (iter as f64 - gamma_down as f64) / training_sample as f64
        };

        let (w_vec, v_vec) =
            plain_nlgd_iteration(&train_set, w_data, v_data, degree_of_sigmoid, gamma, eta)?;

        w_data = w_vec;
        v_data = v_vec;

        alpha0 = alpha1;
        alpha1 = (1.0 + (1.0 + 4.0 * alpha0 * alpha0).sqrt()) / 2.0;
    }

    let (correct, auc) = calculate_auc(&test_set, &w_data)?;
    Ok((w_data, correct, auc))
}

/// Normalizes a data set in-place.
fn normalize_data_inplace(dataset: &mut Dataset) -> anyhow::Result<()> {
    let maximum_abs_values = vec![0.0 as f64; get_factor_len(&dataset)?];

    // Compute the maximum value for each column/factor
    let maximum_abs_values = dataset.iter().fold(maximum_abs_values, |acc, row| {
        acc.iter()
            .zip(row.iter())
            .map(|(x, y)| x.abs().max(y.abs()))
            .collect()
    });

    // Divide each column by the maximum value vector
    dataset.iter_mut().for_each(|row| {
        row.iter_mut()
            .zip(maximum_abs_values.iter())
            .for_each(|(d, m)| {
                *d /= *m;
            })
    });
    Ok(())
}

/// Returns the length of each row in the data set.  All rows are assumed to have the
/// same length, and the input `dataset` is assumed to have at least one row.
fn get_factor_len(dataset: &[Vec<f64>]) -> anyhow::Result<usize> {
    match dataset.first() {
        // No element in the dataset
        None => Err(anyhow!("empty dataset")),
        Some(first) => Ok(first.len()),
    }
}

/// Consumes `w_data` and `v_data` and returns updated values.
fn plain_nlgd_iteration(
    dataset: &[Vec<f64>],
    w_data: Vec<f64>,
    v_data: Vec<f64>,
    approximate_degree: u64,
    gamma: f64,
    eta: f64,
) -> anyhow::Result<(Vec<f64>, Vec<f64>)> {
    let ip_vec = plain_ip(&dataset, &v_data)?;
    let grad_vec = plain_sigmoid(&dataset, &ip_vec, approximate_degree, gamma)?;
    let (w_data, v_data) = plain_nlgd_step(w_data, v_data, grad_vec, eta)?;
    Ok((w_data, v_data))
}

/// Multply the matrix in dataset by `w_data`.
fn plain_ip(dataset: &[Vec<f64>], data_vec: &[f64]) -> anyhow::Result<Vec<f64>> {
    if get_factor_len(&dataset)? != data_vec.len() {
        return Err(anyhow!("bad factor len"));
    }

    Ok(dataset.iter().fold(Vec::new(), |mut rst, row| {
        rst.push(
            row.iter()
                .zip(data_vec.iter())
                .fold(0.0, |acc, (x, y)| acc + (x * y)),
        );
        rst
    }))
}

// Look-up tables for sigmoid computations.
static DEGREE_3: &[f64] = &[-0.5, 0.15012, -0.001593];
static DEGREE_5: &[f64] = &[-0.5, 0.19131, -0.0045963, 0.0000412332];
static DEGREE_7: &[f64] = &[-0.5, 0.216884, -0.00819276, 0.000165861, -0.00000119581];

/// ASSUME approximate_degree == 3 or approximate_degree == 5 or approximate_degree == 7.
/// Do scalar multiplication between ip_vec and DEGREE_* then multiply with dataset.
fn plain_sigmoid(
    dataset: &[Vec<f64>],
    ip_vec: &[f64],
    approximate_degree: u64,
    gamma: f64,
) -> anyhow::Result<Vec<f64>> {
    if dataset.len() != ip_vec.len() {
        return Err(anyhow!("bad input len"));
    }
    let init_grad = vec![0.0 as f64; get_factor_len(dataset)?];
    let rst = dataset
        .iter()
        .zip(ip_vec.iter())
        .fold(init_grad, |grad, (row, ip_item)| {
            row.iter()
                .zip(grad.iter())
                .map(|(data_item, grad_item)| {
                    //TODO
                    let weight = if approximate_degree == 3 {
                        DEGREE_3[0] + DEGREE_3[1] * ip_item + DEGREE_3[2] * ip_item.powi(3)
                    } else if approximate_degree == 5 {
                        DEGREE_5[0]
                            + DEGREE_5[1] * ip_item
                            + DEGREE_5[2] * ip_item.powi(3)
                            + DEGREE_5[3] * ip_item.powi(5)
                    } else {
                        // approximate_degree == 7
                        DEGREE_7[0]
                            + DEGREE_7[1] * ip_item
                            + DEGREE_7[2] * ip_item.powi(3)
                            + DEGREE_7[3] * ip_item.powi(5)
                            + DEGREE_7[4] * ip_item.powi(7)
                    };
                    grad_item + weight * data_item
                })
                .collect()
        });

    Ok(rst.iter().map(|i| i * gamma).collect())
}

/// Consumes `w_data`, `v_data`, and `grad` and returns new `w_data` and `v_data` values.
fn plain_nlgd_step(
    w_data: Vec<f64>,
    v_data: Vec<f64>,
    grad: Vec<f64>,
    eta: f64,
) -> anyhow::Result<(Vec<f64>, Vec<f64>)> {
    let new_w_data: Vec<f64> = v_data.iter().zip(grad.iter()).map(|(v, g)| v - g).collect();
    let new_v_data: Vec<f64> = w_data
        .iter()
        .zip(new_w_data.iter())
        .map(|(w, t)| (1.0 - eta) * t + eta * w)
        .collect();
    Ok((new_w_data, new_v_data))
}

/// Calculate the quality of the result.
fn calculate_auc(dataset: &[Vec<f64>], w_data: &[f64]) -> anyhow::Result<(f64, f64)> {
    let mut tn = 0.0 as f64;
    let mut fp = 0.0 as f64;
    let mut theta_tn = Vec::new();
    let mut theta_fp = Vec::new();

    for row in dataset.iter() {
        let y_value = row.first().ok_or_else(|| anyhow!("empty row"))?;

        // These two iters are slices that do not include the first element
        let mut row_iter = row.iter();
        row_iter.next();
        let mut w_data_iter = w_data.iter();
        w_data_iter.next();

        if y_value > &0.0 {
            if true_ip(&row, &w_data)? < 0.0 {
                tn += 1.0;
            }
            theta_tn.push(y_value * true_ip(row_iter.as_slice(), w_data_iter.as_slice())?);
        } else {
            if true_ip(&row, &w_data)? < 0.0 {
                fp += 1.0;
            }
            theta_fp.push(y_value * true_ip(row_iter.as_slice(), w_data_iter.as_slice())?);
        }
    }

    let correctness = 100.0 - (100.0 * (tn + fp) / dataset.len() as f64);

    let auc = theta_tn.iter().fold(0.0 as f64, |acc_tn, t| {
        theta_fp
            .iter()
            .fold(acc_tn, |acc_fp, f| acc_fp + if f <= t { 1.0 } else { 0.0 })
    });
    let auc = auc / (theta_tn.len() * theta_fp.len()) as f64;
    Ok((correctness, auc))
}

fn true_ip(lhs: &[f64], rhs: &[f64]) -> anyhow::Result<f64> {
    if lhs.len() != rhs.len() {
        return Err(anyhow!("lhs/rhs len mismatch"));
    }
    Ok(lhs
        .iter()
        .zip(rhs.iter())
        .fold(0.0 as f64, |acc, (l, r)| acc + l * r))
}

/// Entry point.  Reads an arbitrary number of input datasets, one from each source, concatenates
/// them together into a single compound dataset, then trains a logistic regressor on this new
/// dataset.  Input and output are assumed to be encoded in Pinecone.
fn main() -> anyhow::Result<()> {
    for path in fs::read_dir("/input/idash2017")? {
        let path = path?.path();
        println!("path in: {:?}", path);
        let file_name = path.file_name().ok_or(anyhow!("cannot get file name"))?;
        println!("file name {:?}", file_name);
        let (mut train_set, mut test_set, num_of_iter, degree_of_sigmoid, gamma_up, gamma_down) =
            read_inputs(&path)?;
        let (w_data, correct, auc) = nlgd(
            &mut train_set,
            &mut test_set,
            num_of_iter,
            degree_of_sigmoid,
            gamma_up,
            gamma_down,
        )?;
        println!("result: {:?}, {:?}, {:?}", w_data, correct, auc);
        let result_encode = pinecone::to_vec::<(Vec<f64>, f64, f64)>(&(w_data, correct, auc))?;
        let mut output = PathBuf::from("/output/idash2017/");
        output.push(file_name);
        println!("output {:?}", output);
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(output)?
            .write(&result_encode)?;
    }
    Ok(())
}
