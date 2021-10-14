//! Wrapper around the all IceCap crates used by the Runtime Manager.
//!
//! These crates only exist in the context of the IceCap build, so bundling them all together
//! allows the build system to replace them all at once with a dummy outside of the context of the
//! IceCap build system.
//!
//! This will be unecessary once we have per-isolate backend workspaces.
//!
//! The source of these crates can be found at:
//!
//! https://gitlab.com/arm-research/security/icecap/icecap/-/tree/main/src/rust/icecap
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub use icecap_core;
pub use icecap_start_generic;
pub use icecap_std_external;
pub use icecap_event_server_types;
