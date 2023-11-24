//! Veracruz policy parsers
//!
//! This module contains a collection of various parsers useful for building
//! a policy file. These are mostly used by the top-level programs to provide
//! useful command-line interfaces.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(dead_code)]

use crate::pipeline::Expr;
use lalrpop_util::lalrpop_mod;
#[cfg(feature = "std")]
use std::path;
use anyhow::Result;

lalrpop_mod!(pipeline);

/// parser for a single file path either in the form of
/// --program a.wasm or --program b=a.wasm if a file should
/// be provided as a different name.
///
/// Note we can't fail, because a malformed string may be
/// interpreted as a really ugly filename. Fortunately these
/// sort of mistakes should still be caught by a later
/// "file-not-found" error.
#[cfg(feature = "std")]
pub fn parse_renamable_path(s: &str) -> Result<(String, path::PathBuf)> {
    match s.splitn(2, '=').collect::<Vec<_>>().as_slice() {
        [name, path] => Ok((String::from(*name), path::PathBuf::from(*path))),
        [path] => Ok((String::from(*path), path::PathBuf::from(*path))),
        _ => unreachable!(),
    }
}

/// parser for file paths either in the form of
/// --program a.wasm or --program b=a.wasm if a file should
/// be provided as a different name.
///
/// Also accepts comma-separated lists of files.
///
/// Note we can't fail, because a malformed string may be
/// interpreted as a really ugly filename. Fortunately these
/// sort of mistakes should still be caught by a later
/// "file-not-found" error.
#[cfg(feature = "std")]
pub fn parse_renamable_paths(s: &str) -> Result<Vec<(String, path::PathBuf)>> {
    s.split(',')
        .map(|s| parse_renamable_path(s.as_ref()))
        .collect::<Result<Vec<_>, _>>()
}

/// Parse a pineline string `pipeline_str` and return the syntax tree.
pub fn parse_pipeline(pipeline_str: &str) -> anyhow::Result<Box<Expr>> {
    let engine = pipeline::ExprsParser::new();

    // NOTE: not sure why the parse need a 'static str, use the box to escape and rebox
    let tmp: &'static str = Box::leak(Box::new(pipeline_str.to_owned().into_boxed_str()));
    let rst = engine.parse(&tmp)?.clone();
    // Re-box so the tmp will drop
    let _ = unsafe { Box::from_raw(tmp as *const str as *mut str) };
    Ok(rst)
}
