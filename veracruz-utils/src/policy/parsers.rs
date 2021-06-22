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
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "std")]
use std::{
    ffi,
    path,
};

/// parser for a single file path either in the form of
/// --program a.wasm or --program b:a.wasm if a file should
/// be provided as a different name.
///
/// Note we can't fail, because a malformed string may be
/// interpreted as a really ugly filename. Fortunately these
/// sort of mistakes should still be caught by a later
/// "file-not-found" error.
#[cfg(feature = "std")]
pub fn parse_renamable_path(
    s: &ffi::OsStr
) -> Result<(String, path::PathBuf), ffi::OsString> {
    let s = s.to_str()
        .ok_or_else(|| ffi::OsString::from(format!("invalid path: {:?}", s)))?;

    // TODO should we actually use = as a separator? more
    // common in CLIs
    match s.splitn(2, ":").collect::<Vec<_>>().as_slice() {
        [name, path] => Ok((
            String::from(*name),
            path::PathBuf::from(*path)
        )),
        [path] => Ok((
            String::from(*path),
            path::PathBuf::from(*path)
        )),
        _ => unreachable!(),
    }
}

/// parser for file paths either in the form of
/// --program a.wasm or --program b:a.wasm if a file should
/// be provided as a different name.
///
/// Also accepts comma-separated lists of files.
///
/// Note we can't fail, because a malformed string may be
/// interpreted as a really ugly filename. Fortunately these
/// sort of mistakes should still be caught by a later
/// "file-not-found" error.
#[cfg(feature = "std")]
pub fn parse_renamable_paths(
    s: &ffi::OsStr
) -> Result<Vec<(String, path::PathBuf)>, ffi::OsString> {
    let s = s.to_str()
        .ok_or_else(|| ffi::OsString::from(format!("invalid path: {:?}", s)))?;

    s.split(",")
        .map(|s| parse_renamable_path(s.as_ref()))
        .collect::<Result<Vec<_>, _>>()
}

