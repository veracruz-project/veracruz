//! Transport protocol build script
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

extern crate protoc_rust;

fn main() {
    println!("cargo:rerun-if-changed=protos/transport_protocol.proto");

    protoc_rust::run(protoc_rust::Args {
        out_dir: "src/",
        input: &["protos/transport_protocol.proto"],
        includes: &["protos"],
        customize: protoc_rust::Customize {
            ..Default::default()
        },
    })
    .expect("protoc");
}
