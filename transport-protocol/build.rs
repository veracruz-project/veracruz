//! Transport protocol build script
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

fn main() {
    // https://github.com/jgarzik/rust-protobuf-example
    // somehow works without this:
    println!("cargo:rerun-if-changed=protos/transport_protocol.proto");

    protobuf_codegen::Codegen::new()
        .cargo_out_dir("protos")
        .includes(&["protos"])
        .input("protos/transport_protocol.proto")
        .run_from_script();
}
