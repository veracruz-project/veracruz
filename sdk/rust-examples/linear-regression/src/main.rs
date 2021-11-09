//! A simple linear-regression example
//!
//! ## Context
//!
//! A relatively-low powered device (think e.g. an M-class microcontroller, or similar)
//! wants to offload some heavy, complex calculation to a third-party---here represented by a linear
//! regression problem.  The owner of the device wishes to ensure that the computation was
//! faithfully executed---that is, the results are trustworthy and are definitely the output of a
//! linear regression algorithm---and also are kept secret from third parties wishing to see what is
//! happening on the device.
//!
//! Inputs:                  1.
//! Assumed form of inputs:  one Pinecode-encoded `Vec<(f64, f64)>` representing a dataset of (x, y)
//!                          co-ordinates from which a linear relationship is to be extracted.
//! Ensured form of outputs: A Pinecode-encoded `LinearRegression` struct (see below) consisting of
//!                          a gradient and a Y-intercept, representing the best linear fit for the
//!                          input data.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow;
use serde::Serialize;
use std::fs;

/// Reads the single input dataset, which is assumed to be a Bincode-encoded
/// vector of 64-bit float pairs.  Fails with
/// `return_code::ErrorCode::DataSourceCount` if there is not exactly one input,
/// and fails with `return_code::ErrorCode::BadInput` if the input cannot be
/// decoded from `pinecone` into a Rust vector of floating-point pairs.
fn read_input() -> anyhow::Result<Vec<(f64, f64)>> {
    let input = fs::read("/input/linear-regression.dat")?;
    Ok(pinecone::from_bytes(&input)?)
}

/// The result of a linear regression is a line which is encoded as a gradient
/// and intercept.
#[derive(Serialize)]
struct LinearRegression {
    /// Gradient of the linear relationship.
    gradient: f64,
    /// Y-intercept of the linear relationship.
    intercept: f64,
}

/// Computes the respective means of two columns of data.
fn means(dataset: &[(f64, f64)]) -> (f64, f64) {
    let mut xsum: f64 = 0.0;
    let mut ysum: f64 = 0.0;

    let length = dataset.len();

    for (x, y) in dataset.iter() {
        xsum += *x;
        ysum += *y;
    }

    (xsum / length as f64, ysum / length as f64)
}

/// The linear regression algorithm: takes two columns of "training" data and
/// extracts the best linear relationship that describes this data.  Returns a
/// `LinearRegression` struct which describes the gradient and y-intercept of
/// the learnt linear model.
fn linear_regression(data: &[(f64, f64)]) -> LinearRegression {
    let (xmean, ymean) = means(&data);

    let mut n: f64 = 0.0;
    let mut d: f64 = 0.0;

    for datum in data {
        n += (datum.0 - xmean) * (datum.1 - ymean);
        d += (datum.0 - xmean) * (datum.0 - xmean);
    }

    LinearRegression {
        gradient: n / d,
        intercept: ymean - (n / d) * xmean,
    }
}

/// Entry point.  The program expects a single data item, which is expected to
/// be a Rust vector of pairs of `f64` values.  Writes back a Bincode-encoded
/// `LinearRegression` struct as output.  Whoever receives the result is assumed
/// to know how to decode the result.
fn main() -> anyhow::Result<()> {
    let data = read_input()?;
    let result = linear_regression(&data);
    let result_encode = pinecone::to_vec(&result)?;
    fs::write("/output/linear-regression.dat", result_encode)?;
    Ok(())
}
