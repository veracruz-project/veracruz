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
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{exit, Command},
    str::FromStr,
};

use chrono::{DateTime, Datelike, FixedOffset, Timelike};
use clap::{App, Arg};
use data_encoding::HEXLOWER;
use log::{error, info};
use ring::digest::{digest, SHA256};
use serde_json::{json, to_string_pretty, Value};
use veracruz_utils::policy::{
    policy::Policy,
    error::PolicyError,
    expiry::Timepoint,
    principal::{ExecutionStrategy, Identity, Program, FileRights},
};
use wasi_types::Rights;

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

/// About the utility..
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
/// Runtime Manager enclave for SGX.
const DD_EXECUTABLE_NAME: &'static str = "dd";
/// The name of the 'xxd' executable to call when computing the hash of the
/// Runtime Manager enclave for SGX.
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
#[derive(Debug)]
struct Arguments {
    /// The filenames of cryptographic certificates associated to each principal
    /// in the computation.
    certificates: Vec<PathBuf>,
    /// The capabilities associated to each principal and program in the computation.
    /// Note that the length of this vector MUST match the total length of `certificates` and `program_binary` 
    /// as each principal and program has an accompanying capability table.
    certificate_capabilities: Vec<Vec<String>>,
    binary_capabilities: Vec<Vec<String>>,
    /// The socket address (IP and port) of the Veracruz server instance.
    veracruz_server_ip: Option<SocketAddr>,
    /// The socket address (IP and port) of the Veracruz proxy attestation instance.
    proxy_attestation_server_ip: Option<SocketAddr>,
    /// The filename of the Runtime Manager CSS file for SGX measurement.  This is
    /// optional.
    css_file: Option<PathBuf>,
    /// The filename of the Runtime Manager PRCR0 file for Nitro Enclave
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
    /// The filename of the WASM program.
    program_binaries: Vec<PathBuf>,
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
            certificate_capabilities: Vec::new(),
            binary_capabilities: Vec::new(),
            veracruz_server_ip: None,
            proxy_attestation_server_ip: None,
            css_file: None,
            pcr0_file: None,
            output_policy_file: PathBuf::new(),
            certificate_expiry: None,
            program_binaries: Vec::new(),
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

/// Checks that all strings appearing in all vectors in the `capabilities` argument are
/// valid Veracruz capabilities: of the form "[FILE_NAME]:[Right_number]".
fn check_capability(capabilities: &[Vec<String>]) {
    if !capabilities.iter().all(|v| {
        v.iter()
            .all(|s| {
                let mut split = s.split(':'); 
                //skip the filename
                split.next();
                let cap_check = match split.next() {
                    None => false,
                    Some(cap) => cap.parse::<u64>().is_ok(),
                };
                //The length must be 2 hence it must be none.
                cap_check || split.next().is_none() 
            })
    }) {
        abort_with("Could not parse the capability command line arguments.");
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
            Arg::with_name("capability")
                .short("p")
                .long("capability")
                .value_name("CAPABILITIES")
                .help("The capability table of a client or a program of the form 'output:rw,input-0:w,prorgam.wasm:x' where each entry is separated by ','")
                .required(true)
                .multiple(true),
        )
        .arg(
            Arg::with_name("veracruz-server-ip")
                .short("s")
                .long("veracruz-server-ip")
                .value_name("IP ADDRESS")
                .help("IP address of the Veracruz server.")
                .required(true),
        )
        .arg(
            Arg::with_name("proxy-attestation-server-ip")
                .short("t")
                .long("proxy-attestation-server-ip")
                .value_name("IP ADDRESS")
                .help("IP address of the Veracruz proxy attestation server.")
                .required(true),
        )
        .arg(
            Arg::with_name("css-file")
                .short("b")
                .long("css-file")
                .value_name("FILE")
                .help("Filename of the CSS file for the Runtime Manager enclave for SGX measurement.")
                .required(false),
        )
        .arg(
            Arg::with_name("pcr-file")
                .short("l")
                .long("pcr-file")
                .value_name("FILE")
                .help("Filename of the PCR0 file for the Runtime Manager enclave for AWS Nitro Enclave measurement.")
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
            Arg::with_name("binary")
                .short("w")
                .long("binary")
                .value_name("FILE")
                .help("Specifies the filename of the WASM binary to use for the computation.")
                .required(true)
                .multiple(true),
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

    if let Some(binaries) = matches.values_of("binary") {
        arguments.program_binaries = binaries.map(|b| PathBuf::from(b)).collect();
    } else {
        abort_with("No program binary filename passed as an argument.");
    }

    if let Some(capabilities) = matches.values_of("capability") {
        let mut capabilities = capabilities
            .map(|s| s.split(",").map(|s| String::from(s)).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        check_capability(&capabilities);

        if arguments.certificates.len() + arguments.program_binaries.len() != capabilities.len() {
            abort_with("The number of capabilities attributes differ from the total number of certificate and binary attributes.");
        }
        let binary_capabilities = capabilities.split_off(arguments.certificates.len());

        arguments.certificate_capabilities = capabilities;
        arguments.binary_capabilities = binary_capabilities;
    } else {
        abort_with("No capabilities were passed as command line parameters.");
    }

    if let Some(url) = matches.value_of("veracruz-server-ip") {
        if let Ok(url) = SocketAddr::from_str(url) {
            arguments.veracruz_server_ip = Some(url);
        } else {
            abort_with("Could not parse the Veracruz server IP address argument.");
        }
    } else {
        abort_with("No Veracruz server IP address was passed as a command line parameter.");
    }

    if let Some(url) = matches.value_of("proxy-attestation-server-ip") {
        if let Ok(url) = SocketAddr::from_str(url) {
            arguments.proxy_attestation_server_ip = Some(url);
        } else {
            abort_with("Could not parse Veracruz proxy attestation server IP address argument.");
        }
    } else {
        abort_with("No Veracruz proxy attestation server IP address was passed as a command line parameter.");
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
        info!("No PCR0 file was passed as a command line parameter.  Nitro hashes will not be computed.");
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
fn compute_program_hash(argument: &PathBuf) -> String {
    if let Ok(mut file) = File::open(argument) {
        let mut buffer = vec![];

        file.read_to_end(&mut buffer).expect("Failed to read file.");

        return pretty_digest(&mut buffer);
    } else {
        abort_with("Failed to open WASM program binary.");
    }
}

/// Computes the SGX hash of the Runtime Manager enclave making use of the external
/// 'dd' and 'xxd' utilities, which are called as external processes.  Returns
/// `None` iff no `css.bin` file was provided as a command-line argument.
fn compute_sgx_enclave_hash(arguments: &Arguments) -> Option<String> {
    info!("Computing Intel SGX Enclave hash.");

    let css_file = match &arguments.css_file {
        None => return None,
        Some(css_file) => css_file,
    };

    if Path::new(css_file).exists() {
        let mut dd_command = Command::new(DD_EXECUTABLE_NAME);
        
        dd_command
            .arg("skip=960")
            .arg("count=32")
            .arg(format!("if={}", pretty_pathbuf(css_file.clone())))
            .arg(format!("of={}", "hash.bin"))
            .arg("bs=1");

        info!("Invoking 'dd' executable: {:?}.", dd_command);

        if let Ok(output) = dd_command.output() {
            if !output.status.success() {
                abort_with("Invocation of 'dd' command failed.");
            }

            let mut xxd_command = Command::new(XXD_EXECUTABLE_NAME);

            xxd_command
                .arg("-ps")
                .arg("-cols")
                .arg("32")
                .arg("hash.bin");

            info!("Invoking 'xxd' executable: {:?}.", xxd_command);

            if let Ok(hash_hex) = xxd_command.output()
            {
                if !hash_hex.status.success() {
                    abort_with("Invocation of 'xxd' command failed.");
                }

                if let Ok(mut hash_hex) = String::from_utf8(hash_hex.stdout) {
                    hash_hex = hash_hex.replace("\n", "");

                    info!("Hash successfully computed, {}.", hash_hex);

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
        error!("Runtime Manager CSS.bin file cannot be opened.");
        error!("Continuing on without computing an SGX hash.");
        None
    }
}

/// Reads the Runtime Manager PCR0 file content, munging it a little, for the Nitro
/// Enclave hash.  Returns `None` iff no `pcr0` file was provided as a command
/// line argument.
fn compute_nitro_enclave_hash(arguments: &Arguments) -> Option<String> {
    info!("Computing AWS Nitro Enclave hash.");
    
    let pcr0_file = match &arguments.pcr0_file {
        None => return None,
        Some(pcr0_file) => pcr0_file,
    };

    if let Ok(mut file) = File::open(pcr0_file) {
        let mut content = String::new();

        file.read_to_string(&mut content)
            .expect("Failed to read file.");

        content = content.replace("\n", "");

        info!("Hash successfully computed, {}.", content);

        Some(content)
    } else {
        info!("Runtime Manager PCR0 file cannot be opened.");
        info!("Continuing on without computing a Nitro hash.");
        None
    }
}

// HACK attestation not yet implemented for IceCap
fn compute_icecap_enclave_hash(arguments: &Arguments) -> Option<String> {
    Some("deadbeefdeadbeefdeadbeefdeadbeeff00dcafef00dcafef00dcafef00dcafe".to_string())
}

/// Serializes the identities of all principals in the Veracruz computation into
/// a vec of VeracruzIdentity<String>.
fn serialize_identities(arguments: &Arguments) -> Vec<Identity<String>> {
    info!("Serializing identities of computation Principals.");
    
    assert_eq!(arguments.certificates.len(), arguments.certificate_capabilities.len());
    
    let mut values = Vec::new();

    for (id, (cert, capability)) in arguments
        .certificates
        .iter()
        .zip(&arguments.certificate_capabilities)
        .enumerate()
    {
        if let Ok(mut file) = File::open(cert) {
            let mut content = String::new();

            file.read_to_string(&mut content)
                .expect("Failed to read file.");

            let certificates = content.replace("\n", "")
                                 .replace("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")
                                 .replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");
            let file_permissions = serialize_capability(capability);

            values.push(Identity::new(
                certificates,
                id as u32,
                file_permissions,
            ));
        } else {
            abort_with("Could not open certificate file.");
        }
    }
    values
}

/// Serializes the identities of all principals in the Veracruz computation into
/// a vec of VeracruzProgram.
fn serialize_binaries(arguments: &Arguments) -> Vec<Program> {
    info!("Serializing programs.");
    
    assert_eq!(arguments.program_binaries.len(), arguments.binary_capabilities.len());
    
    let mut values = Vec::new();

    for (id, (program_file_name, capability)) in arguments
        .program_binaries
        .iter()
        .zip(&arguments.binary_capabilities)
        .enumerate()
    {
        let pi_hash = compute_program_hash(program_file_name);
        let file_permissions = serialize_capability(capability);

        values.push(Program::new(
            program_file_name.to_str().expect(&format!("Failed to convert {:?} to str",program_file_name)).trim().to_string(),
            id as u32,
            pi_hash,
            file_permissions,
        ));
    }
    values
}

/// Serializes the enclave server certificate expiry timepoint to a JSON value,
/// computing the time when the certificate will expire as a point relative to
/// the current time.
fn serialize_enclave_certificate_timepoint(arguments: &Arguments) -> Timepoint {
    info!("Serializing enclave certificate expiry timepoint.");
    
    let timepoint = arguments
        .certificate_expiry
        .expect("Internal invariant failed: certificate lifetime is missing.");

    Timepoint::new(
        timepoint.year() as u32,
        timepoint.month() as u8,
        timepoint.day() as u8,
        timepoint.hour() as u8,
        timepoint.minute() as u8,
    ).expect("Failed to instantiate a timepoint")
}

#[inline]
fn serialize_capability(cap_string : &[String]) -> Vec<FileRights> {
    cap_string.iter().map(|c| serialize_capability_entry(c.as_str())).collect()
}

fn serialize_capability_entry(cap_string : &str) -> FileRights {
    let mut split = cap_string.split(':'); 
    let file_name = split.next().expect(&format!("Failed to parse {}, empty string", cap_string));
    let string_number = split
                .next()
                .expect(&format!("Failed to parse `{}`, contain no `:`", cap_string));
    let number = string_number
                .trim()
                .parse::<u32>()
                .expect(&format!("Failed to parse {}, not a u64", string_number));
    // check if this is a valid number
    let _cap = Rights::from_bits(number as u64)
                .expect(&format!("Failed to parse {}, not a u64 representing WASI Right", number));
    FileRights::new(file_name.trim().to_string(),number)
}

fn serialize_execution_strategy(strategy: &str) -> ExecutionStrategy {
    if strategy == "Interpretation"
    { 
        return ExecutionStrategy::Interpretation 
    } else if strategy == "JIT" {
        return ExecutionStrategy::JIT
    } else {
        abort_with("Could not parse execution strategy argument.");
    }
}

/// Serializes the Veracruz policy file as a JSON value.
///
/// NOTE: we are glossing over TrustZone attestation for the moment, so we use
/// the measurement of the SGX enclave as the measurement of the TrustZone
/// trusted application, too.
fn serialize_json(arguments: &Arguments) -> Value {
    info!("Serializing JSON policy file.");

    let sgx_hash = compute_sgx_enclave_hash(arguments);
    let policy = Policy::new(
        serialize_identities(arguments),
        serialize_binaries(arguments),
        format!("{}", &arguments.veracruz_server_ip.as_ref().expect(&format!("Failed to get the veracruz server ip"))),
        serialize_enclave_certificate_timepoint(arguments),
        POLICY_CIPHERSUITE.to_string(),
        sgx_hash.clone(),
        // TODO should be tz_hash
        sgx_hash.clone(),
        compute_nitro_enclave_hash(arguments),
        compute_icecap_enclave_hash(arguments),
        format!("{}", &arguments.proxy_attestation_server_ip.as_ref().expect(&format!("Failed to get the proxy attestation server ip"))),
        arguments.enclave_debug_mode,
        serialize_execution_strategy(&arguments.execution_strategy),
    ).expect("Failed to instantiate a (struct) policy");

    json!(policy)
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

/// Entry point: reads the command line, serializes the policy file to JSON, and
/// then writes the serialized JSON to the specified output file.
fn main() {
    env_logger::init();

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
