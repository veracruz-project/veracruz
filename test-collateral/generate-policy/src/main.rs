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

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{exit, Command},
    str::FromStr,
};

use chrono::{DateTime, Datelike, FixedOffset, Timelike};
use clap::{App, Arg};
use data_encoding::HEXLOWER;
use log::info;
use ring::digest::{digest, SHA256};
use serde_json::{json, to_string_pretty, Value, Value::String as JsonString};
use url::Url;

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous useful functions.
////////////////////////////////////////////////////////////////////////////////

/// Aborts the program with a message on `stderr`.
fn abort_with<T>(msg: T) -> !
where
    T: Into<String>,
{
    eprintln!("{}", msg.into());
    exit(1);
}

/// Pretty-prints a `PathBuf`, aborting if this cannot be done.
fn pretty_pathbuf(buf: PathBuf) -> String {
    if let Ok(s) = buf.into_os_string().into_string() {
        return s.clone();
    } else {
        abort_with("Failed to pretty-print path.");
    }
}

/// Pretty-prints the SHA256 digest of the input `buf` into a lowercase
/// hex-formatted string.
fn pretty_digest(mut buf: &[u8]) -> String {
    let digest = digest(&SHA256, &mut buf);

    HEXLOWER.encode(digest.as_ref())
}

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

/// The name of the 'dd' executable to call when computing the hash of the
/// Mexico City enclave for SGX.
const DD_EXECUTABLE_NAME: &'static str = "dd";
/// The name of the 'xxd' executable to call when computing the hash of the
/// Mexico City enclave for SGX.
const XXD_EXECUTABLE_NAME: &'static str = "xxd";

/// The default filename of the output JSON policy file, if no alternative is
/// provided on the command line.
const DEFAULT_OUTPUT_FILENAME: &'static str = "output.json";
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
    certificates: Vec<PathBuf>,
    /// The roles associated to each principal in the computation.  Note that
    /// length of the two vectors, `certificates` and `roles`, must match as
    /// each certificate has an accompanying set of roles to form a compound
    /// "identity".
    roles: Vec<Vec<String>>,
    /// The URL of the Sinaloa instance.
    sinaloa_url: Option<Url>,
    /// The URL of the Tabasco instance.
    tabasco_url: Option<Url>,
    /// The filename of the Mexico City CSS file for SGX measurement.  This is
    /// optional.
    css_file: Option<PathBuf>,
    /// The filename of the Mexico City PRCR0 file for Nitro Enclave
    /// measurement.  This is optional.
    pcr0_file: Option<PathBuf>,
    /// The filename of the output policy file.
    output_policy_file: PathBuf,
    /// The expiry timepoint of the server certificate.  This is not optional,
    /// we use the value of `None` as a marker indicating that the field has not
    /// yet been intiialized, due to `DateTime` not really having an obvious
    /// default value.  Past command-line parsing, any value of `None` in this
    /// field is an internal invariant failure.
    certificate_expiry: Option<DateTime<FixedOffset>>,
    /// The data provisioning order.
    data_provisioning_order: Vec<i32>,
    /// The streaming provisioning order.
    streaming_provisioning_order: Vec<i32>,
    /// The filename of the WASM program.
    program_binary: PathBuf,
    /// Whether the enclave will be started in debug mode, with reduced
    /// protections against snooping and interference, and with the ability to
    /// write to the host's `stdout`.
    enclave_debug_mode: bool,
    /// Describes the execution strategy (interpretation or JIT) that will be
    /// used for the computation.
    execution_strategy: String,
}

impl Arguments {
    /// Creates a new `Arguments` structure with all fields set to empty (with
    /// the `enclave_debug_mode` flag set to `false`, and the
    /// `certificate_lifetime` field set to `0`).
    #[inline]
    pub fn new() -> Self {
        Arguments {
            certificates: Vec::new(),
            roles: Vec::new(),
            sinaloa_url: None,
            tabasco_url: None,
            css_file: None,
            pcr0_file: None,
            output_policy_file: PathBuf::new(),
            certificate_expiry: None,
            data_provisioning_order: Vec::new(),
            streaming_provisioning_order: Vec::new(),
            program_binary: PathBuf::new(),
            enclave_debug_mode: false,
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
        abort_with("Could not parse execution strategy argument.");
    }
}

/// Checks that all strings appearing in all vectors in the `roles` argument are
/// valid Veracruz roles: "ResultReceiver", "DataProvider", or "ProgramProvider".
fn check_roles(roles: &[Vec<String>]) {
    if !roles.iter().all(|v| {
        v.iter()
            .all(|s| s == "ResultReader" || s == "DataProvider" || s == "ProgramProvider")
    }) {
        abort_with("Could not parse the role command line arguments.");
    }
}

/// Parses the command line options, building a `CommandLineOptions` struct out
/// of them.  If required options are not present, or if any options are
/// malformed, this will abort the program.
fn parse_command_line() -> Arguments {
    let default_debug = DEFAULT_DEBUG_STATUS.to_string();

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
                .long("roles")
                .value_name("ROLES")
                .help("The set of roles of a computation participant, comma separated.")
                .required(true)
                .multiple(true)
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
            Arg::with_name("css-file")
                .short("b")
                .long("css-file")
                .value_name("FILE")
                .help("Filename of the CSS file for the Mexico City enclave for SGX measurement.")
                .required(false),
        )
        .arg(
            Arg::with_name("pcr-file")
                .short("l")
                .long("pcr-file")
                .value_name("FILE")
                .help("Filename of the PCR0 file for the Mexico City enclave for AWS Nitro Enclave measurement.")
                .required(false),
        )
        .arg(
            Arg::with_name("output-policy-file")
                .short("o")
                .long("output-policy-file")
                .value_name("FILE")
                .help("Filename of the generated policy file.")
                .default_value(DEFAULT_OUTPUT_FILENAME)
                .required(true),
        )
        .arg(
            Arg::with_name("certificate-expiry")
                .short("x")
                .long("certificate-expiry")
                .value_name("RFC2822 TIMEPOINT")
                .help(
                    "The expiry point of the server certificate, expressed \
as an RFC-2822 formatted timepoint.",
                )
                .required(true),
        )
        .arg(
            Arg::with_name("data-provision-order")
                .short("p")
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
                .short("w")
                .long("binary")
                .value_name("FILE")
                .help("Specifies the filename of the WASM binary to use for the computation.")
                .required(true),
        )
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("enclave-debug-mode")
                .help(
                    "Specifies whether the Veracruz trusted runtime should allow debugging \
information to be produced by the executing WASM binary.",
                )
                .required(true)
                .value_name("BOOLEAN")
                .default_value(&default_debug),
        )
        .arg(
            Arg::with_name("execution-strategy")
                .short("e")
                .long("execution-strategy")
                .help(
                    "Specifies whether to use interpretation or JIT execution for the WASM \
binary.",
                )
                .required(true)
                .default_value(DEFAULT_EXECUTION_STRATEGY),
        )
        .get_matches();

    info!("Parsed command line.");

    let mut arguments = Arguments::new();

    if let Some(certificates) = matches.values_of("certificate") {
        arguments.certificates = certificates.map(|c| PathBuf::from(c)).collect();
    } else {
        abort_with("No certificates were passed as command line parameters.");
    }

    if let Some(roles) = matches.values_of("role") {
        let roles = roles
            .map(|s| s.split(",").map(|s| String::from(s)).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        check_roles(&roles);

        arguments.roles = roles;
    } else {
        abort_with("No roles were passed as command line parameters.");
    }

    if arguments.certificates.len() != arguments.roles.len() {
        abort_with("The number of certificates and role attributes differ.");
    }

    if let Some(url) = matches.value_of("sinaloa-url") {
        if let Ok(url) = Url::parse(url) {
            arguments.sinaloa_url = Some(url);
        } else {
            abort_with("Could not parse Sinaloa URL argument.");
        }
    } else {
        abort_with("No Sinaloa URL was passed as a command line parameter.");
    }

    if let Some(url) = matches.value_of("tabasco-url") {
        if let Ok(url) = Url::parse(url) {
            arguments.tabasco_url = Some(url);
        } else {
            abort_with("Could not parse Tabasco URL argument.");
        }
    } else {
        abort_with("No Tabasco URL was passed as a command line parameter.");
    }

    if let Some(fname) = matches.value_of("output-policy-file") {
        arguments.output_policy_file = PathBuf::from(fname);
    } else {
        info!("No output filename passed as an argument.  Using a default.");
        arguments.output_policy_file = PathBuf::from(DEFAULT_OUTPUT_FILENAME);
    }

    if let Some(fname) = matches.value_of("css-file") {
        arguments.css_file = Some(PathBuf::from(fname));
    } else {
        info!(
            "No CSS file was passed as a command line parameter.  SGX hashes will not be computed."
        );
    }

    if let Some(fname) = matches.value_of("pcr-file") {
        arguments.pcr0_file = Some(PathBuf::from(fname));
    } else {
        info!("No PCR0 file was passed as a command line parameter, Nitro hashes will not be computed.");
    }

    if let Some(expiry) = matches.value_of("certificate-expiry") {
        if let Ok(expiry) = DateTime::parse_from_rfc2822(expiry) {
            arguments.certificate_expiry = Some(expiry);
        } else {
            abort_with("The certificate expiry timepoint argument could not be parsed.");
        }
    } else {
        abort_with("No certificate lifetime passed as an argument.");
    }

    if let Some(data_provisioning_order) = matches.values_of("data-provision-order") {
        let mut parsed = Vec::new();

        for value in data_provisioning_order {
            if let Ok(i) = i32::from_str(value) {
                parsed.push(i);
            } else {
                abort_with("Could not parse data provisioning order argument.");
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
                abort_with("Could not parse streaming provisioning order argument.");
            }
        }

        arguments.streaming_provisioning_order = parsed;
    }

    if let Some(binary) = matches.value_of("binary") {
        arguments.program_binary = PathBuf::from(binary);
    } else {
        abort_with("No program binary filename passed as an argument.");
    }

    if let Some(debug) = matches.value_of("debug") {
        if let Ok(debug) = bool::from_str(debug) {
            arguments.enclave_debug_mode = debug;
        } else {
            abort_with("The debug flag could not be parsed.");
        }
    } else {
        info!("No debug flag passed as an argument.  Using a default.");
        arguments.enclave_debug_mode = DEFAULT_DEBUG_STATUS;
    }

    if let Some(strategy) = matches.value_of("execution-strategy") {
        check_execution_strategy(strategy);
        arguments.execution_strategy = String::from(strategy);
    } else {
        info!("No execution strategy passed as an argument.  Using a default.");
        arguments.execution_strategy = String::from(DEFAULT_EXECUTION_STRATEGY);
    }

    if arguments.pcr0_file.is_none() && arguments.css_file.is_none() {
        abort_with(
            "Either the CSS.bin or the PCR0 file must be provided as a \
command-line parameter.",
        );
    }

    info!("Successfully extracted command line arguments.");

    arguments
}

////////////////////////////////////////////////////////////////////////////////
// JSON serialization.
////////////////////////////////////////////////////////////////////////////////

/// Executes the hashing program on the WASM binary, returning the computed
/// SHA256 hash as a string.
fn compute_program_hash(arguments: &Arguments) -> String {
    if let Ok(mut file) = File::open(&arguments.program_binary) {
        let mut buffer = vec![];

        file.read_to_end(&mut buffer).expect("Failed to read file.");

        return pretty_digest(&mut buffer);
    } else {
        abort_with("Failed to open WASM program binary.");
    }
}

/// Computes the SGX hash of the Mexico City enclave making use of the external
/// 'dd' and 'xxd' utilities, which are called as external processes.  Returns
/// `None` iff no `css.bin` file was provided as a command-line argument.
fn compute_sgx_enclave_hash(arguments: &Arguments) -> Option<String> {
    let css_file = match &arguments.css_file {
        None => return None,
        Some(css_file) => css_file,
    };

    if Path::new(css_file).exists() {
        if let Ok(output) = Command::new(DD_EXECUTABLE_NAME)
            .arg("skip=960")
            .arg("count=32")
            .arg(format!("if={}", pretty_pathbuf(css_file.clone())))
            .arg(format!("of={}", "hash.bin"))
            .output()
        {
            if !output.status.success() {
                abort_with("Invocation of 'dd' command failed.");
            }

            if let Ok(hash_hex) = Command::new(XXD_EXECUTABLE_NAME)
                .arg("-ps")
                .arg("-cols")
                .arg("32")
                .arg("hash.bin")
                .output()
            {
                if !hash_hex.status.success() {
                    abort_with("Invocation of 'xxd' command failed.");
                }

                if let Ok(mut hash_hex) = String::from_utf8(hash_hex.stdout) {
                    hash_hex = hash_hex.replace("\n", "");

                    return Some(hash_hex);
                } else {
                    abort_with("Failed to parse output of 'xxd'.");
                }
            } else {
                abort_with("Invocation of 'xxd' command failed.");
            }
        } else {
            abort_with("Invocation of 'dd' command failed.");
        }
    } else {
        abort_with("CSS.bin file cannot be opened.");
    }
}

/// Reads the Mexico City PCR0 file content, munging it a little, for the Nitro
/// Enclave hash.  Returns `None` iff no `pcr0` file was provided as a command
/// line argument.
fn compute_nitro_enclave_hash(arguments: &Arguments) -> Option<String> {
    let pcr0_file = match &arguments.pcr0_file {
        None => return None,
        Some(pcr0_file) => pcr0_file,
    };

    if let Ok(mut file) = File::open(pcr0_file) {
        let mut content = String::new();

        file.read_to_string(&mut content)
            .expect("Failed to read file.");

        content = content.replace("\n", "");

        return Some(content);
    } else {
        abort_with("Mexico City PCR0 file cannot be opened.");
    }
}

/// Serializes the identities of all principals in the Veracruz computation into
/// a JSON value.
fn serialize_identities(arguments: &Arguments) -> Value {
    assert_eq!(&arguments.certificates.len(), &arguments.roles.len());

    let mut values = vec![];

    for (id, (cert, roles)) in arguments
        .certificates
        .iter()
        .zip(&arguments.roles)
        .enumerate()
    {
        if let Ok(mut file) = File::open(cert) {
            let mut content = String::new();

            file.read_to_string(&mut content)
                .expect("Failed to read file.");

            content = content.replace(
                "-----BEGIN CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----\\n",
            );
            content = content.replace("-----END CERTIFICATE", "\\n-----END CERTIFICATE");

            let json = json!({
                "certificate": content,
                "id": id,
                "roles": roles,
            });

            values.push(json);
        } else {
            abort_with("Could not open certificate file.");
        }
    }

    json!(values)
}

/// Serializes the enclave server certificate expiry timepoint to a JSON value,
/// computing the time when the certificate will expire as a point relative to
/// the current time.
fn serialize_enclave_certificate_expiry(arguments: &Arguments) -> Value {
    let expiry = arguments
        .certificate_expiry
        .expect("Internal invariant failed: certificate lifetime is missing.");

    json!({
        "year": expiry.year(),
        "month": expiry.month(),
        "day": expiry.day(),
        "hour": expiry.hour(),
        "minute": expiry.minute()
    })
}

/// Serializes the Veracruz policy file as a JSON value.
///
/// NOTE: we are glossing over TrustZone attestation for the moment, so we use
/// the measurement of the SGX enclave as the measurement of the TrustZone
/// trusted application, too.
fn serialize_json(arguments: &Arguments) -> Value {
    info!("Serializing JSON policy file.");

    let mut base_json = json!({
        "identities": serialize_identities(arguments),
        "sinaloa_url": format!("{}", &arguments.sinaloa_url.as_ref().unwrap()),
        "enclave_cert_expiry": serialize_enclave_certificate_expiry(arguments),
        "ciphersuite": POLICY_CIPHERSUITE,
        "tabasco_url": format!("{}", &arguments.tabasco_url.as_ref().unwrap()),
        "data_provision_order": json!(&arguments.data_provisioning_order),
        "streaming_order": json!(&arguments.streaming_provisioning_order),
        "pi_hash": compute_program_hash(arguments),
        "debug": &arguments.enclave_debug_mode,
        "execution_strategy": &arguments.execution_strategy});

    if let Some(sgx_hash) = compute_sgx_enclave_hash(arguments) {
        base_json["mexico_city_hash_sgx"] = JsonString(sgx_hash.clone());
        base_json["mexico_city_hash_tz"] = JsonString(sgx_hash);
    }

    if let Some(nitro_hash) = compute_nitro_enclave_hash(arguments) {
        base_json["mexico_city_hash_nitro"] = JsonString(nitro_hash);
    }

    base_json
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

/// Entry point: reads the command line, serializes the policy file to JSON, and
/// then writes the serialized JSON to the specified output file.
fn main() {
    let arguments = parse_command_line();

    info!(
        "Writing JSON file, {}.",
        pretty_pathbuf(arguments.output_policy_file.clone())
    );

    if let Ok(mut file) = File::create(&arguments.output_policy_file) {
        if let Ok(json) = to_string_pretty(&serialize_json(&arguments)) {
            println!(
                "Writing JSON policy file with SHA256 hash {}.",
                pretty_digest(&mut json.as_bytes())
            );
            write!(file, "{}", json).expect("Failed to write file.");
            info!("JSON file written successfully.");
            exit(0);
        } else {
            abort_with("Failed to prettify serialized JSON.");
        }
    } else {
        abort_with(format!(
            "Could not open file {}.",
            pretty_pathbuf(arguments.output_policy_file.clone())
        ));
    }
}
