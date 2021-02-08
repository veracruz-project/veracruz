//! Veracruz policy generator
//!
//! # AUTHORS
//!
//! The Veracruz Development Team.
//!
//! # COPYRIGHT
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for licensing
//! and copyright information.

use std::{fs::File, io::Write, process::exit, str::FromStr};

use clap::{App, Arg};
use log::info;
use serde_json::{json, to_string_pretty, Value};
use url::Url;

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// About Chihuahua/freestanding-chihuahua/Veracruz.
const ABOUT: &'static str = "A utility for generating Veracruz JSON policy \
files from a series of command line arguments.";
/// The name of the application.
const APPLICATION_NAME: &'static str = "generate-policy";
/// The authors list.
const AUTHORS: &'static str = "The Veracruz Development Team.  See the file \
`AUTHORS.markdown` in the Veracruz root directory for detailed authorship \
information.";
/// The application's version information.
const VERSION: &'static str = "0.1.0";

/// The single supported ciphersuite embedded in the policy file.
const POLICY_CIPHERSUITE: &'static str = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";

/// The default filename of the output JSON policy file, if no alternative is
/// provided on the command line.
const DEFAULT_OUTPUT_FILENAME: &'static str = "output.json";
/// The default expiry of the server certificate (measured in hours, from its
/// creation) if no alternative is provided on the command line.
const DEFAULT_CERTIFICATE_EXPIRY: usize = 8;
/// The default debug status of the Veracruz enclave, if no alternative is
/// provided on the command line.
const DEFAULT_DEBUG_STATUS: bool = false;
/// The default execution strategy for the WASM binary, if no alternative is
/// provided on the command line.
const DEFAULT_EXECUTION_STRATEGY: &'static str = "Interpretation";

////////////////////////////////////////////////////////////////////////////////
// Command line parsing.
////////////////////////////////////////////////////////////////////////////////

/// A structure collating all of the arguments passed to the executable.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Arguments {
    /// The filenames of cryptographic certificates associated to each principal
    /// in the computation.
    certificates: Vec<String>,
    /// The roles associated to each principal in the computation.  Note that
    /// length of the two vectors, `certificates` and `roles`, must match as
    /// each certificate has an accompanying set of roles to form a compound
    /// "identity".
    roles: Vec<Vec<String>>,
    /// The URL of the Sinaloa instance.
    sinaloa_url: Option<Url>,
    /// The URL of the Tabasco instance.
    tabasco_url: Option<Url>,
    /// The filename of the output policy file.
    output_policy_file: String,
    /// The expiry timepoint of the server certificate.  This is measured in
    /// hours.
    certificate_lifetime: usize,
    /// The data provisioning order.
    data_provisioning_order: Vec<i32>,
    /// The streaming provisioning order.
    streaming_provisioning_order: Vec<i32>,
    /// The filename of the WASM program.
    program_binary: String,
    /// The debug flag.
    debug: bool,
    /// Describes the execution strategy (interpretation or JIT) that will be
    /// used for the computation.
    execution_strategy: String,
}

impl Arguments {
    /// Creates a new `Arguments` structure with all fields set to empty (with
    /// the `debug` flag set to `false`, and the `certificate_lifetime` field
    /// set to `0`).
    #[inline]
    pub fn new() -> Self {
        Arguments {
            certificates: Vec::new(),
            roles: Vec::new(),
            sinaloa_url: None,
            tabasco_url: None,
            output_policy_file: String::new(),
            certificate_lifetime: 0,
            data_provisioning_order: Vec::new(),
            streaming_provisioning_order: Vec::new(),
            program_binary: String::new(),
            debug: false,
            execution_strategy: String::new(),
        }
    }
}

/// Checks that the string `strategy` matches either "Interpretation" or "JIT",
/// and if not prints an error message and aborts.
fn check_execution_strategy(strategy: &str) {
    if strategy == "Interpretation" || strategy == "JIT" {
        return;
    } else {
        eprintln!("Could not parse execution strategy argument.");
        exit(1);
    }
}

/// Checks that all strings appearing in all vectors in the `roles` argument are
/// valid Veracruz roles: "ResultReceiver", "DataProvider", or "ProgramProvider".
fn check_roles(roles: &[Vec<String>]) {
    if !roles.iter().all(|v| {
        v.iter()
            .all(|s| s == "ResultReceiver" || s == "DataProvider" || s == "ProgramProvider")
    }) {
        eprintln!("Could not parse the role command line arguments.");
        exit(1);
    }
}

/// Parses the command line options, building a `CommandLineOptions` struct out
/// of them.  If required options are not present, or if any options are
/// malformed, this will abort the program.
fn parse_command_line() -> Arguments {
    let matches = App::new(APPLICATION_NAME)
        .version(VERSION)
        .author(AUTHORS)
        .about(ABOUT)
        .arg(
            Arg::with_name("certificate")
                .short("c")
                .long("certificate")
                .value_name("FILE")
                .help("The filename of a cryptographic certificate identifying a computation participant.")
                .required(true)
                .multiple(true),
        )
        .arg(
            Arg::with_name("role")
                .short("r")
                .long("role")
                .value_name("ROLES")
                .help("The set of roles of a computation participant, comma separated.")
                .required(true)
                .multiple(true),
        )
        .arg(
            Arg::with_name("sinaloa-url")
                .short("s")
                .long("sinaloa-url")
                .value_name("URL")
                .help("URL of the Sinaloa server.")
                .required(true),
        )
        .arg(
            Arg::with_name("tabasco-url")
                .short("t")
                .long("tabasco-url")
                .value_name("URL")
                .help("URL of the Tabasco server.")
                .required(true),
        )
        .arg(
            Arg::with_name("output-policy-file")
                .short("o")
                .long("output-policy-file")
                .value_name("FILE")
                .help("Filename of the generated policy file.")
                .default_value("output.json")
                .required(true),
        )
        .arg(
            Arg::with_name("certificate-lifetime-in-hours")
                .short("l")
                .long("certificate-lifetime-in-hours")
                .value_name("LIFETIME")
                .help(
                    "Describes the expiry lifetime of the server certificate, measured in \
hours.",
                )
                .default_value("8")
                .required(true),
        )
        .arg(
            Arg::with_name("data-provision-order")
                .short("f")
                .long("data-provision-order")
                .value_name("ORDER")
                .help("Specifies the data provisioning order.")
                .required(false),
        )
        .arg(
            Arg::with_name("stream-provision-order")
                .short("a")
                .long("stream-provision-order")
                .value_name("ORDER")
                .help("Specifies the streaming provisioning order.")
                .required(false),
        )
        .arg(
            Arg::with_name("binary")
                .short("b")
                .long("binary")
                .value_name("FILE")
                .help("Specifies the filename of the WASM binary to use for the computation.")
                .required(true),
        )
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .help(
                    "Specifies whether the Veracruz trusted runtime should allow debugging \
information to be produced by the executing WASM binary.",
                )
                .required(true)
                .default_value("false"),
        )
        .arg(
            Arg::with_name("execution-strategy")
                .short("x")
                .long("execution-strategy")
                .help(
                    "Specifies whether to use interpretation or JIT execution for the WASM \
binary.",
                )
                .required(true)
                .default_value("interpretation"),
        )
        .get_matches();

    info!("Parsed command line.");

    let mut arguments = Arguments::new();

    if let Some(certificates) = matches.values_of("certificate") {
        arguments.certificates = certificates.map(|s| String::from(s)).collect();
    } else {
        eprintln!("No certificates were passed as command line parameters.");
        exit(-1);
    }

    if let Some(roles) = matches.values_of("role") {
        let roles = roles
            .map(|s| s.split(",").map(|s| String::from(s)).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        check_roles(&roles);

        arguments.roles = roles;
    } else {
        eprintln!("No roles were passed as command line parameters.");
        exit(-1);
    }

    if arguments.certificates.len() != arguments.roles.len() {
        eprintln!("The number of certificates and role attributes differ.");
        exit(1)
    }

    if let Some(url) = matches.value_of("sinaloa-url") {
        if let Ok(url) = Url::parse(url) {
            arguments.sinaloa_url = Some(url);
        } else {
            eprintln!("Could not parse Sinaloa URL argument.");
            exit(1);
        }
    } else {
        eprintln!("No Sinaloa URL was passed as a command line parameter.");
        exit(1);
    }

    if let Some(url) = matches.value_of("tabasco-url") {
        if let Ok(url) = Url::parse(url) {
            arguments.tabasco_url = Some(url);
        } else {
            eprintln!("Could not parse Tabasco URL argument.");
            exit(1);
        }
    } else {
        eprintln!("No Tabasco URL was passed as a command line parameter.");
        exit(1);
    }

    if let Some(fname) = matches.value_of("output-policy-file") {
        arguments.output_policy_file = String::from(fname);
    } else {
        info!("No output filename passed as an argument.  Using a default.");
        arguments.output_policy_file = String::from(DEFAULT_OUTPUT_FILENAME);
    }

    if let Some(lifetime) = matches.value_of("certificate-lifetime-in-hours") {
        if let Ok(lifetime) = usize::from_str(lifetime) {
            arguments.certificate_lifetime = lifetime;
        } else {
            eprintln!("The certificate lifetime argument could not be parsed.");
            exit(1);
        }
    } else {
        info!("No certificate lifetime passed as an argument.  Using a default.");
        arguments.certificate_lifetime = DEFAULT_CERTIFICATE_EXPIRY;
    }

    if let Some(data_provisioning_order) = matches.values_of("data-provision-order") {
        let mut parsed = Vec::new();

        for value in data_provisioning_order {
            if let Ok(i) = i32::from_str(value) {
                parsed.push(i);
            } else {
                eprintln!("Could not parse data provisioning order argument.");
                exit(1);
            }
        }

        arguments.data_provisioning_order = parsed;
    }

    if let Some(streaming_provisioning_order) = matches.values_of("stream-provision-order") {
        let mut parsed = Vec::new();

        for value in streaming_provisioning_order {
            if let Ok(i) = i32::from_str(value) {
                parsed.push(i);
            } else {
                eprintln!("Could not parse streaming provisioning order argument.");
                exit(1);
            }
        }

        arguments.streaming_provisioning_order = parsed;
    }

    if let Some(binary) = matches.value_of("binary") {
        arguments.program_binary = String::from(binary);
    } else {
        eprintln!("No program binary filename passed as an argument.");
        exit(1);
    }

    if let Some(debug) = matches.value_of("debug") {
        if let Ok(debug) = bool::from_str(debug) {
            arguments.debug = debug;
        } else {
            eprintln!("The debug flag could not be parsed.");
            exit(1);
        }
    } else {
        info!("No debug flag passed as an argument.  Using a default.");
        arguments.debug = DEFAULT_DEBUG_STATUS;
    }

    if let Some(strategy) = matches.value_of("execution-strategy") {
        check_execution_strategy(strategy);
        arguments.execution_strategy = String::from(strategy);
    } else {
        info!("No execution strategy passed as an argument.  Using a default.");
        arguments.execution_strategy = String::from(DEFAULT_EXECUTION_STRATEGY);
    }

    info!("Successfully extracted command line arguments.");

    arguments
}

////////////////////////////////////////////////////////////////////////////////
// JSON serialization.
////////////////////////////////////////////////////////////////////////////////

/// Serializes the enclave server certificate expiry timepoint to a JSON value.
fn serialize_enclave_certificate_expiry(arguments: &Arguments) -> Value {
    json!({
        "year": "",
        "month": "",
        "day": "",
        "hour": "",
        "minute": ""
    })
}

/// Serializes the Veracruz policy file as a JSON value.
fn serialize_json(arguments: &Arguments) -> Value {
    info!("Serializing JSON policy file.");

    let identities = "";

    let sinaloa_url = format!("{}", &arguments.sinaloa_url.as_ref().unwrap());
    let tabasco_url = format!("{}", &arguments.tabasco_url.as_ref().unwrap());

    let enclave_cert_expiry = serialize_enclave_certificate_expiry(arguments);
    let ciphersuite = POLICY_CIPHERSUITE;

    let data_provision_order = "";
    let streaming_order = "";

    let pi_hash = "";
    let debug = &arguments.debug;
    let execution_strategy = &arguments.execution_strategy;

    json!({
        "identities": identities,
        "sinaloa_url": sinaloa_url,
        "enclave_cert_expiry": enclave_cert_expiry,
        "ciphersuite": ciphersuite,
        "tabasco_url": tabasco_url,
        "data_provision_order": data_provision_order,
        "streaming_order": streaming_order,
        "pi_hash": pi_hash,
        "debug": debug,
        "execution_strategy": execution_strategy,
    })
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

/// Entry point: reads the command line, serializes the policy file to JSON, and
/// then writes the serialized JSON to the specified output file.
fn main() {
    let arguments = parse_command_line();

    info!("Writing JSON file, {}.", arguments.output_policy_file);

    if let Ok(mut file) = File::create(&arguments.output_policy_file) {
        if let Ok(json) = to_string_pretty(&serialize_json(&arguments)) {
            write!(file, "{}", json);
            info!("JSON file written successfully.");
            exit(0);
        } else {
            eprintln!("Failed to prettify serialized JSON.");
            exit(1);
        }
    } else {
        eprintln!("Could not open file {}.", arguments.output_policy_file);
        exit(1);
    }
}
