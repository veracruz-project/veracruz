//! Logistic regression example, using an off-the-shelf Rust library for machine learning.
//!
//! ## Context
//!
//! A number of competing supermarkets want to collectively pool some of their data on
//! customer preferences to be able to better compete against their larger competitors.  However,
//! as each individual supermarket does not trust any other supermarket in the computation, each
//! would like to keep their respective datasets private, lest one of their competitors use it to
//! lure customers their way.  The supermarkets do agree, however, that a logistic regression model
//! should be learnt over the combined datasets, and made available to all.  Other than that, no
//! supermarket wants to reveal anything about their data to any other.
//!
//! Inputs:                  An arbitrary number.
//! Assumed form of inputs:  an arbitrary number of Pinecone-encoded Rust `Dataset` structs (see
//!                          below).
//! Ensured form of outputs: A Pinecone-encoded Rust vector of `f64` values describing the
//!                          parameters of the learnt logistic regression model.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing and copyright
//! information.

use anyhow::anyhow;
use rusty_machine::{
    learning::{logistic_reg::LogisticRegressor, SupModel},
    linalg::{Matrix, Vector},
};
use serde::Deserialize;
use std::fs;

/// This is a row of the input that each contributor to the computation
/// provides: it consists of a vector, representing an N-dimension
/// floating-point valued point, along with a single binary value capturing the
/// classification of the point into one of two classes.
#[derive(Deserialize, Clone)]
struct PointAndClassification {
    /// The point to be classified,
    point: Vec<f64>,
    /// The classification of the point.
    classification: bool,
}

impl PointAndClassification {
    /// Returns the dimension of the point to be classified.
    pub fn dimension(&self) -> usize {
        self.point.len()
    }

    /// Returns an `f64` value corresponding to the classification (1.0 if
    /// `true` and 0.0 if not).
    pub fn classification(&self) -> f64 {
        if self.classification {
            1.0
        } else {
            0.0
        }
    }
}

/// This is the input that each input provider supplies.  It consists of N
/// points and their associated classification into one of two binary classes.
/// Each input provider is assumed to provide self-consistent data inputs, e.g.
/// all input points must be of the same dimensionality.
#[derive(Deserialize, Clone)]
struct Dataset {
    points: Vec<PointAndClassification>,
}

impl Dataset {
    /// Returns a new, empty dataset.
    pub fn new() -> Self {
        Dataset { points: Vec::new() }
    }

    /// Appends more data to an existing dataset.
    #[inline]
    pub fn append(&mut self, data: Dataset) {
        self.points.extend(data.points.into_iter())
    }

    /// Checks if the dataset is empty.
    #[inline]
    pub fn empty(&self) -> bool {
        self.points.len() == 0
    }

    /// Returns the number of rows of data entries in the dataset.
    #[inline]
    pub fn rows(&self) -> usize {
        self.points.len()
    }

    /// Returns the dimension of each input point in the dataset (assuming the
    /// dataset is self-consistent!).  Returns `None` iff the dataset is empty.
    pub fn dimension(&self) -> Option<usize> {
        if self.points.len() == 0 {
            None
        } else {
            Some(self.points[0].dimension())
        }
    }

    /// Checks all points in the dataset have the same dimension.
    pub fn self_consistent(&self) -> bool {
        let mut d: Option<usize> = None;

        for p in &self.points {
            match d {
                None => d = Some(p.dimension()),
                Some(dim) => {
                    if dim != p.dimension() {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Returns a one-dimensional vector of all the points in the dataset in
    /// `f64` form along with the dimensions (row/column) of the underlying
    /// point matrix.
    pub fn points_one_dimensional_vector(&self) -> (usize, usize, Vec<f64>) {
        if self.points.len() == 0 {
            return (0, 0, Vec::new());
        } else {
            let cols = self.points[0].dimension();
            let rows = self.rows();
            let mut result = Vec::new();
            let cloned = self.clone();

            for i in &cloned.points {
                result.extend_from_slice(&i.point)
            }

            (rows, cols, result)
        }
    }

    /// Returns a one-dimensional vector of all the classifications in the
    /// dataset in `f64` form.
    pub fn classes_one_dimensional_vector(&self) -> Vec<f64> {
        let mut result = Vec::new();

        for i in &self.points {
            result.push(i.classification());
        }

        result
    }
}

/// Flattens a slice/vector of individual datasets into a single, compound
/// dataset.
fn flatten(ds: &[Dataset]) -> Dataset {
    let mut result = Dataset::new();

    for d in ds.iter().cloned() {
        result.append(d)
    }

    result
}

/// Deserializes a Vector of `u8` values into a `Dataset`.  Fails with
/// `return_code::ErrorCode::BadInput` if the bytes cannot be decoded from
/// `pinecone` into a `Dataset` value, or if the dataset is not self-consistent
/// with respect to the dimensions of each of its points.
fn read_dataset(input: &[u8]) -> anyhow::Result<Dataset> {
    let data = pinecone::from_bytes::<Dataset>(input)?;
    if data.self_consistent() {
        Ok(data)
    } else {
        Err(anyhow!("data inconsistent"))
    }
}

/// Deserializes all inputs into `Dataset` values, returning a vector of
/// datasets, one corresponding to each input source.  Fails with
/// `return_code::ErrorCode::BadInput` if the datasets do not share the same
/// dimensionality, or if the deserialization of any of the datasets fails for
/// any reason.
fn read_all_datasets(input: &[Vec<u8>]) -> anyhow::Result<Vec<Dataset>> {
    let mut result = Vec::new();
    let mut dimension: Option<usize> = None;

    for i in input.into_iter() {
        let dataset = read_dataset(&i)?;

        if dataset.empty() {
            continue;
        }

        match dimension {
            None => {
                dimension = Some(
                    dataset
                        .dimension()
                        .ok_or_else(|| anyhow!("empty dimensions"))?,
                )
            }
            Some(dim) => {
                // Unwrap is safe as we have checked that the dataset is not empty.
                if dataset
                    .dimension()
                    .ok_or_else(|| anyhow!("empty dataset"))?
                    != dim
                {
                    return Err(anyhow!("bad dimensions"));
                } else {
                    result.push(dataset);
                }
            }
        }
    }

    Ok(result)
}

/// Reads all input datasets, producing a single, compound dataset containing
/// them all appended together.  Fails with `return_code::ErrorCode::BadInput`
/// if the deserialization of any dataset fails for any reason, or if the
/// datasets have differing dimensionalities.
fn read_input() -> anyhow::Result<Dataset> {
    let i0 = fs::read("/input/logistic-regression-0.dat")?;
    let i1 = fs::read("/input/logistic-regression-1.dat")?;
    let datas = read_all_datasets(&vec![i0, i1])?;
    Ok(flatten(&datas))
}

/// Splits the dataset into a matrix of points-to-classify and a vector of
/// classifications for those points.
fn split_dataset(dataset: &Dataset) -> (Matrix<f64>, Vector<f64>) {
    let (rows, cols, data) = dataset.points_one_dimensional_vector();
    let classes = dataset.classes_one_dimensional_vector();

    (Matrix::new(rows, cols, data), Vector::new(classes))
}

/// Trains a logistic regressor on the input data, returning a vector of learnt
/// parameters.
fn train(dataset: &Dataset) -> anyhow::Result<Vec<f64>> {
    let mut regressor = LogisticRegressor::default();
    let (inputs, targets) = split_dataset(dataset);

    regressor.train(&inputs, &targets)?;

    let parameters = regressor
        .parameters()
        .ok_or_else(|| anyhow!("empty parameters"))?;

    Ok(parameters.to_owned().into_vec())
}

/// Entry point.  Reads an arbitrary number of input datasets, one from each
/// source, concatenates them together into a single compound dataset, then
/// trains a logistic regressor on this new dataset.  Input and output are
/// assumed to be encoded by `pinecone`.
fn main() -> anyhow::Result<()> {
    let dataset = read_input()?;
    let model = train(&dataset)?;
    let result_encode = pinecone::to_vec::<Vec<f64>>(&model)?;
    fs::write("/output/logistic-regression.dat", result_encode)?;
    Ok(())
}
