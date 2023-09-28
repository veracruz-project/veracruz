//! Intersection set-sum example
//!
//! ## Context
//!
//! An internet advertising company wants to provide a mechanism by which their customers
//! using the platform can evaluate the effectiveness of their advertising campaigns in a
//! privacy-preserving way.  To do this, suppose the advertising company maintains a dataset of
//! web-surfers who have viewed a customer's advertisements online.  The customer maintains a
//! dataset of web-surfers who have spent money on their web-store.  The two want to come together
//! and compute the total spend of web-surfers who, having viewed the customer's advertisements,
//! went on to spend money on the customer's store.  Neither the advertising platform nor the
//! web-store want to reveal anything to each other, other than that.
//!
//! Inputs:                  1.
//! Assumed form of inputs:  Postcard-encoded Rust Vectors of (x, y) co-ordinates, expressed as `f64`
//!                          values.
//! Ensured form of outputs: A Postcard-encoded `LinearRegression` struct (see below) consisting of
//!                          a gradient and a Y-intercept, representing the best linear fit for the
//!                          input data.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow;
use serde::Deserialize;
use std::fs;

/// The advertising platform provides a Rust vec filled with `AdvertisementViewer` structs.  These
/// contain the unique identifiers of every web-surfer who viewed the company's advertisements on
/// the platform.
#[derive(Deserialize)]
struct AdvertisementViewer {
    /// Advertisement viewer ID.  It's assumed that advertisement viewer IDs from the
    /// `AdvertisementViewer` struct and customer IDs from the `Customer` struct originate from a
    /// common source, somehow, so that corresponding entries in both datasets can be identified.
    id: String,
}

/// The advertisement platform's customer supplies a Rust vec filled with `Customer` structs.  These
/// contain the unique identifiers (derived from the advertisement platform, somehow) of every
/// customer that visited their site, along with a total dollar amount of how much they spent on
/// the site.
#[derive(Deserialize)]
struct Customer {
    /// Customer ID.  It's assumed that customer IDs from the `Customer` and `AdvertisementViewer`
    /// structs originate from a common source, somehow, so that corresponding entries in both
    /// datasets can be identified.
    id: String,
    /// The total dollar spend.  Yes, we're using a floating-point type to model money.  No, this
    /// doesn't really matter.
    total_spend: f64,
}

/// Reads two input sources from the Veracruz host: the first input source is assumed to be a vector
/// of `AdvertisementViewer` structs, whilst the second is assumed to be a vector of `Customer`
/// structs.  Fails with [`return_code::ErrorCode::BadInput`] if the number of inputs provided is
/// not equal to 2, or if the inputs cannot be deserialized from Bincode.
fn read_inputs() -> anyhow::Result<(Vec<AdvertisementViewer>, Vec<Customer>)> {
    let adverts = fs::read("./input/intersection-advertisement-viewer.dat")?;
    let customs = fs::read("./input/intersection-customer.dat")?;

    let adverts = postcard::from_bytes(&adverts)?;
    let customs = postcard::from_bytes(&customs)?;

    Ok((adverts, customs))
}

/// Computes the intersection set-sum of the input data: finds all customers/advertisement viewers
/// in the respective datasets with the same ID and sums up these points of commonality's total
/// spend on the customer's web-store.
fn intersection_set_sum(vs: &[AdvertisementViewer], cs: &[Customer]) -> f64 {
    let mut running_total = 0.0;

    for v in vs {
        for c in cs {
            if v.id == c.id {
                running_total += c.total_spend;
            }
        }
    }

    running_total
}

/// Entry point.  Deserializes the two inputs, computes the intersection set-sum, and writes the
/// result back to the Veracruz host.  Fails with [`return_code::ErrorCode::BadInput`] if there are
/// not exactly two inputs, or if either input cannot be deserialized from Bincode, and fails with
/// [`return_code::ErrorCode::InvariantFailed`] if the result cannot be serialized to Bincode, or if
/// more than one result is written.
fn main() -> anyhow::Result<()> {
    let (adverts, customs) = read_inputs()?;
    let total = intersection_set_sum(&adverts, &customs);
    let result_encode = postcard::to_allocvec::<f64>(&total)?;
    fs::write("./output/intersection-set-sum.dat", result_encode)?;
    Ok(())
}
