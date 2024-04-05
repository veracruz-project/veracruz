//! Veracruz policy generator
//!
//! # AUTHORS
//!
//! The Veracruz Development Team.
//!
//! # COPYRIGHT
//!
//! See the `LICENSE.md` file in the Veracruz root directory for licensing
//! and copyright information.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Datelike, Timelike};
use clap::Parser;
use data_encoding::HEXLOWER;
use log::{info, warn};
use policy_utils::{
    expiry::Timepoint,
    parsers::parse_renamable_path,
    policy::Policy,
    principal::{ExecutionStrategy, FileHash, FilePermissions, Identity, Service, ServiceSource, Pipeline, Program},
};
use serde_json::{json, to_string_pretty, Value};
use std::{
    fmt::Debug,
    fs::{read_to_string, File},
    io::{Read, Write},
    net::SocketAddr,
    path::PathBuf,
    collections::HashMap,
    sync::{Mutex, atomic::{AtomicU32, Ordering}},
};
use veracruz_utils::sha256::sha256;
use lazy_static::lazy_static;

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous useful functions.
////////////////////////////////////////////////////////////////////////////////

/// Pretty-prints the SHA256 digest of the input `buf` into a lowercase
/// hex-formatted string.
fn pretty_digest(buf: &[u8]) -> String {
    let digest = sha256(buf);
    HEXLOWER.encode(&digest)
}

lazy_static!{
    /// A global buffer to hold all the programs and their hashes during the parsing.
    static ref PROG_HASH : Mutex<Vec<FileHash>> = Mutex::new(Vec::new());
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
`AUTHORS.md` in the Veracruz `docs` subdirectory for detailed authorship \
information.";
/// The application's version information.
const VERSION: &'static str = "0.1.0";

/// The single supported ciphersuite embedded in the policy file.
const POLICY_CIPHERSUITE: &'static str = "TLS1_3_CHACHA20_POLY1305_SHA256";

/// The default filename of the output JSON policy file, if no alternative is
/// provided on the command line.
const DEFAULT_OUTPUT_FILENAME: &'static str = "output.json";
/// The default execution strategy for the WASM binary, if no alternative is
/// provided on the command line.
const DEFAULT_EXECUTION_STRATEGY: &'static str = "JIT";
/// The default maximum amount of memory in MiB available to the isolate if no
/// alternative is provided on the command line.
const DEFAULT_MAX_MEMORY_MIB: u32 = 256;

////////////////////////////////////////////////////////////////////////////////
// Command line parsing.
////////////////////////////////////////////////////////////////////////////////

/// A structure collating all of the arguments passed to the executable.
#[derive(Debug, Parser)]
#[command(name = APPLICATION_NAME, author = AUTHORS, version = VERSION, about = ABOUT, long_about = None, rename_all = "kebab-case")]
struct Arguments {
    /// The filenames of cryptographic certificates associated to each principal
    /// in the computation.
    #[arg(short = 'c', long, value_name = "PATH => PERMISSION", value_parser=participant_parser)]
    certificate: Vec<Identity<String>>,
    /// The socket address (IP and port) of the Veracruz server instance.
    #[arg(long, short = 's', value_name = "IP ADDRESS")]
    veracruz_server_ip: SocketAddr,
    /// The socket address (IP and port) of the Veracruz proxy attestation instance.
    #[arg(long, short = 't', value_name = "IP ADDRESS")]
    proxy_attestation_server_ip: SocketAddr,
    /// The filename of the Proxy Attestation Service certificate
    #[arg(long, value_name = "PATH", value_parser=reading_file_parser)]
    proxy_attestation_server_cert: String,
    /// The filename of the Runtime Manager CSS file for SGX measurement.  This is
    /// optional.
    #[arg(long, short = 'b', value_name = "PATH")]
    css_file: Option<PathBuf>,
    /// The filename of the Runtime Manager PRCR0 file for Nitro Enclave
    /// measurement.  This is optional.
    #[arg(long, short = 'l', value_name = "PATH")]
    pcr0_file: Option<PathBuf>,
    /// The hash of the SEV SNP image. This is optional
    #[arg(long, value_name = "HASH")]
    sevsnp_hash: Option<String>,
    /// The filename of the output policy file.
    #[arg(long, short = 'o', default_value = DEFAULT_OUTPUT_FILENAME, value_name = "PATH")]
    output_policy_file: PathBuf,
    /// The expiry timepoint of the server certificate.  This is not optional,
    /// we use the value of `None` as a marker indicating that the field has not
    /// yet been initialized, due to `DateTime` not really having an obvious
    /// default value.  Past command-line parsing, any value of `None` in this
    /// field is an internal invariant failure.
    #[arg(long, short = 'x', value_name = "RFC2822 TIMEPOINT", value_parser = certificate_expiry_parser)]
    certificate_expiry: Timepoint,
    /// The filename of the WASM program.
    /// Note this is an array of string+path pairs, since a string enclave path
    /// can be provided along with the local file path.
    #[arg(long, short = 'w', value_name = "PATH[=LOCAL_PATH] => PERMISSION", value_parser=binary_parser)]
    program_binary: Vec<Program>,
    #[arg(long, value_name = "SERVICE => DIR", value_parser = service_parser)]
    service: Vec<Service>,
    /// The conditional pipeline of programs to execute.  We parse this eagerly
    /// to check for parsing issues before writing the string to the policy
    /// file.  However, this string is then re-parsed by the Veracruz runtime
    /// as we have no way of writing the binary AST into JSON.
    #[arg(long, value_name = "SCRIPT => PERMISSION", value_parser=pipeline_parser)]
    pipeline: Vec<Pipeline>,
    /// The hash of files.
    /// Note this is an array of string+path pairs, since a string enclave path
    /// can be provided along with the local file path.
    #[arg(long, value_name = "PATH[=LOCAL_PATH]", value_parser=file_hash_parser)]
    hash: Vec<FileHash>,
    /// Describes the execution strategy (interpretation or JIT) that will be
    /// used for the computation.
    #[arg(long, short = 'e', value_name = "Interpretation | JIT", default_value = DEFAULT_EXECUTION_STRATEGY)]
    execution_strategy: ExecutionStrategy,
    /// The maximum amount of memory in MiB available to the isolate. Only
    /// enforced in Nitro for now.
    #[arg(long, short = 'm', value_name = "SIZE", default_value_t = DEFAULT_MAX_MEMORY_MIB)]
    max_memory_mib: u32,
}

impl Arguments {
    /// Parses the command line options, building a `Arguments` struct out
    /// of them.  If required options are not present, or if any options are
    /// malformed, this will abort the program.
    fn parse_command_line() -> Result<Self> {
        Ok(Arguments::parse())
    }

    /// Serializes the Veracruz policy file as a JSON value.
    fn serialize_json(mut self) -> Result<Value> {
        info!("Serializing JSON policy file.");

        let linux_hash = self.compute_linux_enclave_hash()?;
        let nitro_hash = self.compute_nitro_enclave_hash()?;

        let mut prog_hash = PROG_HASH.lock().map_err(|e| anyhow!("{e}"))?;
        self.hash.append(&mut prog_hash);
        let policy = Policy::new(
            self.certificate,
            self.program_binary,
            self.service,
            self.pipeline,
            format!("{}", self.veracruz_server_ip),
            self.certificate_expiry,
            POLICY_CIPHERSUITE.to_string(),
            linux_hash,
            nitro_hash,
            self.sevsnp_hash.clone(),
            format!("{}", self.proxy_attestation_server_ip),
            self.proxy_attestation_server_cert,
            self.execution_strategy,
            self.hash,
            self.max_memory_mib,
        )
        .map_err(|_| anyhow!("Failed to instantiate a (struct) policy"))?;

        Ok(json!(policy))
    }

    /// Computes the Linux hash of the Runtime Manager enclave using a SHA256
    /// digest of the runtime manager binary's content.
    fn compute_linux_enclave_hash(&self) -> Result<Option<String>> {
        info!("Computing Linux enclave hash.");

        let css_file = match &self.css_file {
            None => {
                warn!("No Linux CSS file specified.");
                warn!("Continuing without computing a Linux runtime manager hash.");
                None
            }
            Some(css_file) => {
                info!("Measuring content of: {:?}.", css_file);
                info!("Computed sha256sum of Linux CSS file.");
                Some(compute_file_hash(css_file)?)
            }
        };

        Ok(css_file)
    }

    /// Reads the Runtime Manager PCR0 file content, munging it a little, for the Nitro
    /// Enclave hash.  Returns `None` iff no `pcr0` file was provided as a command
    /// line argument.
    fn compute_nitro_enclave_hash(&self) -> Result<Option<String>> {
        info!("Computing AWS Nitro Enclave hash.");

        let pcr0_file = match &self.pcr0_file {
            None => return Ok(None),
            Some(pcr0_file) => pcr0_file,
        };

        let mut file = File::open(pcr0_file)
            .map_err(|_| anyhow!("Runtime Manager PCR0 file cannot be opened."))?;
        let mut content = String::new();

        file.read_to_string(&mut content)?;

        content = content.replace("\n", "");
        // Nitro Enclave hashes are computed using SHA384, which produces 48
        // bytes. We only have room right now for 32 byte hashes.
        // Thus, we need to truncate down to 32 bytes (64 hex characters)
        content = content[0..64].to_string();

        info!("Hash successfully computed, {}.", content);

        Ok(Some(content))
    }

}

/// Executes the hashing program on a file, returning the computed
/// SHA256 hash as a string.
fn compute_file_hash(argument: &PathBuf) -> Result<String> {
    let mut file = File::open(argument)
        .map_err(|_| anyhow!("Failed to open file for hasing: {:?}.", argument))?;
    let mut buffer = vec![];

    file.read_to_end(&mut buffer).map_err(|e| {
        anyhow!(
            "Failed to read file: {:?}.  Error produced: {}.",
            argument,
            e
        )
    })?;

    Ok(pretty_digest(&mut buffer))
}

////////////////////////////////////////////////////////////////////////////////
// Parser.
////////////////////////////////////////////////////////////////////////////////

fn reading_file_parser(input: &str) -> Result<String> {
    Ok(read_to_string(input.trim())?)
}

/// Parse the permission "(DIR:PERMISSION)[,(DIR:PERMISSION)]*"
fn parse_permission(input: &str) -> Result<HashMap<PathBuf, FilePermissions>> {
    input
        .split(",")
        .fold(Ok(HashMap::new()), |acc, c|{
            let mut acc = acc?;
            let (k,v) = parse_permission_entry(c)?;
            acc.insert(k,v);
            Ok(acc)
        })
}

fn parse_permission_entry(cap_string: &str) -> Result<(PathBuf, FilePermissions)> {
    match cap_string.splitn(2,':').collect::<Vec<_>>().as_slice() {
        [file_name, permission] => {
        // If the the cap contains char more than "rwx", the `all` call returns false.
            if !permission.trim().chars().all(|c| c == 'r' || c == 'w' || c == 'x') {
                 return Err(anyhow!("Failed to parse permission entry"));
            }

            Ok((PathBuf::from(file_name.trim()), FilePermissions {
                read: permission.contains("r"),
                write: permission.contains("w"),
                execute: permission.contains("x"),
            }))

        }
        _ => Err(anyhow!("Failed to parse permission entry")),
    }
}

fn participant_parser(input: &str) -> Result<Identity<String>> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    match input.splitn(2,"=>").collect::<Vec<_>>().as_slice() {
        [cert, permission] => {
            let certificate = read_to_string(cert.trim())?
                        .replace("\n", "")
                        .replace(
                            "-----BEGIN CERTIFICATE-----",
                            "-----BEGIN CERTIFICATE-----\n",
                        )
                        .replace(
                            "-----END CERTIFICATE-----",
                            "\n-----END CERTIFICATE-----"
                        );
            let file_permissions = parse_permission(permission.trim())?;
            Ok(Identity::new(certificate, COUNTER.fetch_add(1, Ordering::SeqCst), file_permissions))
        }
        _ => Err(anyhow!("Error in parsing participant"))
    }
}

fn binary_parser(input: &str) -> Result<Program> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    match input.splitn(2,"=>").collect::<Vec<_>>().as_slice() {
        [path, permission] => {
            let (path, local) = parse_renamable_path(path.trim())?;
            let file_permissions = parse_permission(permission.trim())?;
            PROG_HASH.lock().map_err(|e| anyhow!("{e}"))?.push(FileHash::new(path.clone(), compute_file_hash(&local)?));
            Ok(Program::new(path.to_string(), COUNTER.fetch_add(1, Ordering::SeqCst), file_permissions))
        }
        _ => Err(anyhow!("Error in parsing binary"))
    }
}

fn pipeline_parser(input: &str) -> Result<Pipeline> {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    match input.splitn(2,"=>").collect::<Vec<_>>().as_slice() {
        [pipeline, permission] => {
            let file_permissions = parse_permission(permission.trim())?;
            let id = COUNTER.fetch_add(1, Ordering::SeqCst);
            Pipeline::new(
                id.to_string(),
                id,
                pipeline.to_string(),
                file_permissions,
            )
        }
        _ => Err(anyhow!("Error in parsing binary"))
    }
}

fn service_parser(input: &str) -> Result<Service> {
    match input.splitn(2,"=>").collect::<Vec<_>>().as_slice() {
        [source, dir] => {
            // TODO distinguish internal and provisional
            Ok(Service::new(ServiceSource::Internal(source.trim().to_string()), PathBuf::from(dir.trim())))
        }
        _ => Err(anyhow!("Error in parsing service"))
    }
}

fn certificate_expiry_parser(input: &str) -> Result<Timepoint> {
    let timepoint = DateTime::parse_from_rfc2822(input)?;
    Ok(Timepoint::new(
        timepoint.year() as u32,
        timepoint.month() as u8,
        timepoint.day() as u8,
        timepoint.hour() as u8,
        timepoint.minute() as u8,
    )?)
}

fn file_hash_parser(input: &str) -> Result<FileHash> {
    let (path, local) = parse_renamable_path(input)?;
    let hash = compute_file_hash(&local)?;
    Ok(FileHash::new(path.clone(), hash))

}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

/// Entry point: reads the command line, serializes the policy file to JSON, and
/// then writes the serialized JSON to the specified output file.
fn main() -> Result<()> {
    env_logger::init();

    let arguments = Arguments::parse_command_line()?;

    info!("Writing JSON file, {:?}.", arguments.output_policy_file);

    let mut file = File::create(&arguments.output_policy_file)
        .map_err(|_| anyhow!("Could not open file {:?}.", arguments.output_policy_file))?;

    let json = to_string_pretty(&arguments.serialize_json()?)
        .map_err(|_| anyhow!("Failed to prettify serialized JSON."))?;
    info!(
        "Writing JSON policy file with SHA256 hash {}.",
        pretty_digest(&mut json.as_bytes())
    );

    write!(file, "{}", json).expect("Failed to write file.");
    info!("JSON file written successfully.");

    Ok(())
}
