//! Veracruz policy generator
//!
//! # AUTHORS
//!
//! The Veracruz Development Team.
//!
//! # COPYRIGHT
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
//! and copyright information.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Datelike, FixedOffset, Timelike};
use clap::{Arg, ArgAction};
use data_encoding::HEXLOWER;
use log::{info, warn};
use policy_utils::{
    expiry::Timepoint,
    parsers::{enforce_leading_slash, parse_renamable_paths},
    policy::Policy,
    principal::{
        ExecutionStrategy, FileHash, FileRights, Identity, NativeModule, NativeModuleType,
        Pipeline, Program,
    },
};
use regex::Regex;
use serde_json::{json, to_string_pretty, Value};
use std::{
    convert::TryFrom,
    fmt::Debug,
    fs::{read_to_string, File},
    io::{Read, Write},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};
use veracruz_utils::sha256::sha256;
use wasi_types::Rights;

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous useful functions.
////////////////////////////////////////////////////////////////////////////////

/// Pretty-prints the SHA256 digest of the input `buf` into a lowercase
/// hex-formatted string.
fn pretty_digest(buf: &[u8]) -> String {
    let digest = sha256(buf);
    HEXLOWER.encode(&digest)
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
    pipeline_capabilities: Vec<Vec<String>>,
    /// The socket address (IP and port) of the Veracruz server instance.
    veracruz_server_ip: SocketAddr,
    /// The socket address (IP and port) of the Veracruz proxy attestation instance.
    proxy_attestation_server_ip: SocketAddr,
    /// The filename of the Proxy Attestation Service certificate
    proxy_service_cert: PathBuf,
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
    /// yet been initialized, due to `DateTime` not really having an obvious
    /// default value.  Past command-line parsing, any value of `None` in this
    /// field is an internal invariant failure.
    certificate_expiry: DateTime<FixedOffset>,
    /// The filename of the WASM program.
    ///
    /// Note this is an array of string+path pairs, since a string enclave path
    /// can be provided along with the local file path.
    program_binaries: Vec<(String, PathBuf)>,
    /// A list of native module names.
    native_modules_names: Vec<String>,
    /// A list of paths to native module entry points.
    native_modules_entry_points: Vec<PathBuf>,
    /// A list of paths to native module special files.
    native_modules_special_files: Vec<PathBuf>,
    /// The conditional pipeline of programs to execute.  We parse this eagerly
    /// to check for parsing issues before writing the string to the policy
    /// file.  However, this string is then re-parsed by the Veracruz runtime
    /// as we have no way of writing the binary AST into JSON.
    pipelines: Vec<String>,
    /// The hash of files.
    ///
    /// Note this is an array of string+path pairs, since a string enclave path
    /// can be provided along with the local file path.
    hashes: Vec<(String, PathBuf)>,
    /// Whether the enclave will be started in debug mode, with reduced
    /// protections against snooping and interference, and with the ability to
    /// write to the host's `stdout`.
    enclave_debug_mode: bool,
    /// Describes the execution strategy (interpretation or JIT) that will be
    /// used for the computation.
    execution_strategy: String,
    /// Whether clock functions (`clock_getres()`, `clock_gettime()`) should be
    /// enabled.
    enable_clock: bool,
    /// The maximum amount of memory in MiB available to the isolate. Only
    /// enforced in Nitro for now.
    max_memory_mib: u32,
}

impl Arguments {
    /// Parses the command line options, building a `Arguments` struct out
    /// of them.  If required options are not present, or if any options are
    /// malformed, this will abort the program.
    fn parse_command_line() -> Result<Self> {
        let matches = clap::Command::new(APPLICATION_NAME)
            .version(VERSION)
            .author(AUTHORS)
            .about(ABOUT)
            .disable_help_flag(true)
            .arg(
                Arg::new("certificate")
                    .short('c')
                    .long("certificate")
                    .value_name("FILE")
                    .help("The filename of a cryptographic certificate identifying a computation participant.")
                    .required(true)
                    .num_args(1)
                    .action(ArgAction::Append)
            )
            .arg(
                Arg::new("capability")
                    .short('p')
                    .long("capability")
                    .value_name("CAPABILITIES")
                    .help("The capability table of a client or a program of the form 'output:rw,input-0:w,program.wasm:w' where each entry is separated by ','. These may be either some combination of 'r' and 'w' for reading and writing permissions respectively, or an integer containing the bitwise-or of the low-level WASI capabilities.")
                    .required(true)
                    .num_args(1)
                    .action(ArgAction::Append)
            )
            .arg(
                Arg::new("veracruz-server-ip")
                    .short('s')
                    .long("veracruz-server-ip")
                    .value_name("IP ADDRESS")
                    .help("IP address of the Veracruz server.")
                    .num_args(1)
                    .required(true)
            )
            .arg(
                Arg::new("proxy-attestation-server-ip")
                    .short('t')
                    .long("proxy-attestation-server-ip")
                    .value_name("IP ADDRESS")
                    .help("IP address of the Veracruz proxy attestation server.")
                    .num_args(1)
                    .required(true)
            )
            .arg(
                Arg::new("proxy-attestation-server-cert")
                    .long("proxy-attestation-server-cert")
                    .value_name("PROXY_CERT")
                    .help("CA Certificate that the proxy attestation service uses to create and sign certificates")
                    .num_args(1)
                    .required(true)
            )
            .arg(
                Arg::new("css-file")
                    .short('b')
                    .long("css-file")
                    .value_name("FILE")
                    .help("Filename of the CSS file for the Runtime Manager enclave for SGX measurement.")
                    .num_args(1)
                    .required(false)
            )
            .arg(
                Arg::new("pcr-file")
                    .short('l')
                    .long("pcr-file")
                    .value_name("FILE")
                    .help("Filename of the PCR0 file for the Runtime Manager enclave for AWS Nitro Enclave measurement.")
                    .num_args(1)
                    .required(false)
            )
            .arg(
                Arg::new("output-policy-file")
                    .short('o')
                    .long("output-policy-file")
                    .value_name("FILE")
                    .help("Filename of the generated policy file.")
                    .num_args(1)
                )
            .arg(
                Arg::new("certificate-expiry")
                    .short('x')
                    .long("certificate-expiry")
                    .value_name("RFC2822 TIMEPOINT")
                    .help(
                        "The expiry point of the server certificate, expressed \
    as an RFC-2822 formatted timepoint.",
                    )
                    .num_args(1)
                    .required(true)
            )
            .arg(
                Arg::new("program-binary")
                    .short('w')
                    .long("program-binary")
                    .value_name("FILE")
                    .help("Specifies the filename of the WASM binary to use for the computation. \
    This can be of the form \"--program-binary name\" or \"--program-binary enclave_name=path\" if you want to \
    supply the file as a different name in the enclave. Multiple --program-binary flags or a comma-separated \
    list of files may be provided.")
                    .num_args(1)
                    .required(true)
                    .action(ArgAction::Append)
            )
            .arg(
                Arg::new("native-module-name")
                    .long("native-module-name")
                    .value_name("NAME")
                    .help("Specifies the name of the native module to use for the computation. \
    This must be of the form \"--native-module-name name\". Multiple --native-module-name flags may be provided.")
                    .required(false)
                    .action(ArgAction::Append)
            )
            .arg(
                Arg::new("native-module-entry-point")
                    .long("native-module-entry-point")
                    .value_name("FILE")
                    .help("Specifies the path to the entry point of the native module to use for the computation. \
    This must be of the form \"--native-module-entry-point path\". Multiple --native-module-entry-point flags may be provided. \
    If the value is an empty string, the native module is assumed to be static, i.e. part of the Veracruz runtime, \
    and is looked up by name in the static native modules table.")
                    .required(false)
                    .action(ArgAction::Append)
            )
            .arg(
                Arg::new("native-module-special-file")
                    .long("native-module-special-file")
                    .value_name("FILE")
                    .help("Specifies the path to the special file of the native module to use for the computation. \
    This must be of the form \"--native-module-special-file path\". Multiple --native-module-special-file flags may be provided.")
                    .required(false)
                    .action(ArgAction::Append)
            )
            .arg(
                Arg::new("pipeline")
                    //.short('i')
                    .long("pipeline")
                    .value_name("SCRIPT")
                    .help("Script for executing several programs.")
                    .required(false)
                    .action(ArgAction::Append)
            )
            .arg(
                Arg::new("debug")
                    .short('d')
                    .long("enclave-debug-mode")
                    .help(
                        "Specifies whether the Veracruz trusted runtime should allow debugging \
    information to be produced by the executing WASM binary.",
                    )
                    .action(ArgAction::SetTrue)
            )
            .arg(
                Arg::new("execution-strategy")
                    .short('e')
                    .long("execution-strategy")
                    .value_name("Interpretation | JIT")
                    .help(
                        "Specifies whether to use interpretation or JIT execution for the WASM \
    binary.",
                    )
            )
            .arg(
                Arg::new("enable-clock")
                    .short('n')
                    .long("enable-clock")
                    .help(
                        "Specifies whether the Veracruz trusted runtime should allow the WASM \
    binary to call clock functions (`clock_getres()`, `clock_gettime()`).",
                    )
                    .action(ArgAction::SetTrue)
            )
            .arg(
                Arg::new("max-memory-mib")
                    .short('m')
                    .long("max-memory-mib")
                    .value_name("SIZE")
                    .help(
                        "Specifies the maximum amount of memory in MiB available to the isolate. \
    Only enforced in Nitro for now.",
                    )
            )
            .arg(
                Arg::new("hash")
                    .short('h')
                    .long("hashes")
                    .value_name("FILE")
                    .help("Specifies the filename of any (local) file that must match a hash. \
    This can be of the form \"--hash name\" or \"--hash  enclave_name=path\" if you want to \
    supply the file as a different name in the enclave. Multiple --hash flags or a comma-separated \
    list of files may be provided.")
                    .action(ArgAction::Append)
            )
            .get_matches();

        info!("Parsed command line.");

        // Read all clients' certificates
        let certificates = matches
            .get_many::<String>("certificate")
            .ok_or(anyhow!(
                "No certificates were passed as command line parameters."
            ))?
            .map(|c| PathBuf::from(c))
            .collect::<Vec<_>>();

        // Read all program paths
        let mut program_binaries = Vec::new();
        for path_raw in matches
            .get_many::<String>("program-binary")
            .ok_or(anyhow!("No program binary filename passed as an argument."))?
        {
            program_binaries
                .append(&mut parse_renamable_paths(path_raw).map_err(|e| anyhow!("{:?}", e))?);
        }

        // Use the program paths as the base of hashes
        // and append the extra hashes
        let mut hashes = program_binaries.clone();
        if let Some(hashes_raw) = matches.get_many::<String>("hash") {
            for hash_raw in hashes_raw {
                hashes
                    .append(&mut parse_renamable_paths(hash_raw).map_err(|e| anyhow!("{:?}", e))?);
            }
        }

        // Read all native module names
        let native_modules_names = matches
            .get_many::<String>("native-module-name")
            .map_or(Vec::new(), |p| p.map(|s| s.to_string()).collect::<Vec<_>>());

        // Read all native module entry points
        let native_modules_entry_points = matches
            .get_many::<String>("native-module-entry-point")
            .map_or(Vec::new(), |p| {
                p.map(|s| PathBuf::from(s)).collect::<Vec<_>>()
            });

        // Read all native module special files
        let native_modules_special_files = matches
            .get_many::<String>("native-module-special-file")
            .map_or(Vec::new(), |p| {
                p.map(|s| PathBuf::from(s)).collect::<Vec<_>>()
            });

        // Read all the pipelines
        let pipelines = matches
            .get_many::<String>("pipeline")
            .map_or(Vec::new(), |pipelines| {
                pipelines.map(|b| b.to_string()).collect::<Vec<_>>()
            });

        // Check all the capabilities. This includes (1) format and (2) length.
        let mut capabilities = matches
            .get_many::<String>("capability")
            .ok_or(anyhow!(
                "No capabilities were passed as command line parameters."
            ))?
            .map(|s| s.split(",").map(|s| String::from(s)).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        check_capability(&capabilities)?;

        if certificates.len() + program_binaries.len() + pipelines.len() != capabilities.len() {
            return Err(anyhow!("The number of capabilities attributes differ from the total number of certificate and program binary attributes."));
        }

        // Split the capabilities into three groups, certificate, program, and pipeline.
        let mut binary_capabilities = capabilities.split_off(certificates.len());
        let certificate_capabilities = capabilities;
        let pipeline_capabilities = binary_capabilities.split_off(program_binaries.len());

        let veracruz_server_ip =
            SocketAddr::from_str(matches.get_one::<String>("veracruz-server-ip").ok_or(
                anyhow!("No Veracruz server IP address was passed as a command line parameter."),
            )?)?;

        let proxy_attestation_server_ip = SocketAddr::from_str(matches.get_one::<String>("proxy-attestation-server-ip").ok_or(anyhow!("No Veracruz proxy attestation server IP address was passed as a command line parameter."))?)?;

        let proxy_service_cert = PathBuf::from(matches.get_one::<String>("proxy-attestation-server-cert").ok_or(anyhow!("No Proxy Attestation Server certificate filename was passed as a command line parameter."))?);

        let output_policy_file = PathBuf::from(
            matches
                .get_one::<String>("output-policy-file")
                .map_or(DEFAULT_OUTPUT_FILENAME, |fname| fname),
        );

        let css_file = matches
            .get_one::<String>("css-file")
            .map(|fname| PathBuf::from(fname));
        let pcr0_file = matches
            .get_one::<String>("pcr-file")
            .map(|fname| PathBuf::from(fname));
        if css_file.is_none() && pcr0_file.is_none() {
            return Err(anyhow!(
                "Either the CSS.bin or the PCR0 file must be provided as a \
    command-line parameter.",
            ));
        }

        let certificate_expiry = DateTime::parse_from_rfc2822(
            matches
                .get_one::<String>("certificate-expiry")
                .ok_or(anyhow!("No certificate lifetime passed as an argument."))?,
        )?;

        let execution_strategy = String::from(
            matches
                .get_one::<String>("execution-strategy")
                .map_or(DEFAULT_EXECUTION_STRATEGY, |strategy| strategy),
        );
        check_execution_strategy(&execution_strategy)?;

        let enclave_debug_mode = matches.get_flag("debug");
        let enable_clock = matches.get_flag("enable-clock");

        let max_memory_mib =
            if let Some(max_memory_mib) = matches.get_one::<String>("max-memory-mib") {
                max_memory_mib.parse().map_err(|e| {
                    anyhow!(format!(
                        "Failed to parse max memory.  Error produced: {}.",
                        e
                    ))
                })?
            } else {
                info!("No maximum amount of memory passed as an argument.  Using a default.");
                DEFAULT_MAX_MEMORY_MIB
            };

        info!("Successfully extracted command line arguments.");

        Ok(Self {
            certificates,
            certificate_capabilities,
            binary_capabilities,
            pipeline_capabilities,
            veracruz_server_ip,
            proxy_attestation_server_ip,
            proxy_service_cert,
            css_file,
            pcr0_file,
            output_policy_file,
            certificate_expiry,
            program_binaries,
            native_modules_names,
            native_modules_entry_points,
            native_modules_special_files,
            pipelines,
            hashes,
            enclave_debug_mode,
            execution_strategy,
            enable_clock,
            max_memory_mib,
        })
    }

    /// Serializes the Veracruz policy file as a JSON value.
    fn serialize_json(&self) -> Result<Value> {
        info!("Serializing JSON policy file.");

        let policy = Policy::new(
            self.serialize_identities()?,
            self.serialize_binaries()?,
            self.serialize_native_modules()?,
            self.serialize_pipeline()?,
            format!("{}", self.veracruz_server_ip),
            self.serialize_enclave_certificate_timepoint()?,
            POLICY_CIPHERSUITE.to_string(),
            self.compute_linux_enclave_hash()?,
            self.compute_nitro_enclave_hash()?,
            format!("{}", self.proxy_attestation_server_ip),
            self.serialize_proxy_service_certificate()?,
            self.enclave_debug_mode,
            self.serialize_execution_strategy()?,
            self.serialize_file_hash()?,
            self.enable_clock,
            self.max_memory_mib,
        )
        .map_err(|_| anyhow!("Failed to instantiate a (struct) policy"))?;

        Ok(json!(policy))
    }

    /// Serializes the identities of all principals in the Veracruz computation into
    /// a vec of VeracruzIdentity<String>.
    fn serialize_identities(&self) -> Result<Vec<Identity<String>>> {
        info!("Serializing identities of computation Principals.");

        assert_eq!(self.certificates.len(), self.certificate_capabilities.len());

        let mut values = Vec::new();

        for (id, (cert, capability)) in self
            .certificates
            .iter()
            .zip(&self.certificate_capabilities)
            .enumerate()
        {
            let mut file = File::open(cert)
                .map_err(|_| anyhow!("Could not open certificate file {:?}.", cert))?;
            let mut content = String::new();

            file.read_to_string(&mut content)
                .expect("Failed to read file.");

            let certificates = content
                .replace("\n", "")
                .replace(
                    "-----BEGIN CERTIFICATE-----",
                    "-----BEGIN CERTIFICATE-----\n",
                )
                .replace("-----END CERTIFICATE-----", "\n-----END CERTIFICATE-----");
            let file_permissions = serialize_capability(capability)?;

            values.push(Identity::new(certificates, id as u32, file_permissions));
        }
        Ok(values)
    }

    /// Serializes the identities of all principals in the Veracruz computation into
    /// a vec of VeracruzProgram.
    fn serialize_binaries(&self) -> Result<Vec<Program>> {
        info!("Serializing programs.");

        assert_eq!(self.program_binaries.len(), self.binary_capabilities.len());

        let mut result = Vec::new();
        for (id, ((program_file_name, _), capability)) in self
            .program_binaries
            .iter()
            .zip(&self.binary_capabilities)
            .enumerate()
        {
            let file_permissions = serialize_capability(capability)?;
            let program_file_name = enforce_leading_slash(program_file_name).into_owned();

            result.push(Program::new(program_file_name, id as u32, file_permissions));
        }
        Ok(result)
    }

    /// Serializes the native modules used in the computation into a vector.
    fn serialize_native_modules(&self) -> Result<Vec<NativeModule>> {
        info!("Serializing native modules.");

        assert_eq!(
            self.native_modules_names.len(),
            self.native_modules_entry_points.len()
        );
        assert_eq!(
            self.native_modules_entry_points.len(),
            self.native_modules_special_files.len()
        );

        let mut result = Vec::new();
        for ((name, entry_point_path), special_file) in self
            .native_modules_names
            .iter()
            .zip(&self.native_modules_entry_points)
            .zip(&self.native_modules_special_files)
        {
            // Add a backslash (VFS requirement)
            let special_file = enforce_leading_slash(
                special_file
                    .to_str()
                    .ok_or(anyhow!("Fail to convert special_file to str."))?,
            )
            .into_owned();

            let nm_type = if entry_point_path == &PathBuf::from("") {
                NativeModuleType::Static {
                    special_file: PathBuf::from(special_file),
                }
            } else {
                NativeModuleType::Dynamic {
                    special_file: PathBuf::from(special_file),
                    entry_point: entry_point_path.to_path_buf(),
                }
            };
            result.push(NativeModule::new(name.to_string(), nm_type));
        }
        Ok(result)
    }

    /// Serializes the identities of all pipelines.
    fn serialize_pipeline(&self) -> Result<Vec<Pipeline>> {
        info!("Serializing pipelines.");

        assert_eq!(self.pipelines.len(), self.pipeline_capabilities.len());

        let mut result = Vec::new();
        for (id, (preparsed_pipeline, capability)) in self
            .pipelines
            .iter()
            .zip(&self.pipeline_capabilities)
            .enumerate()
        {
            let file_permissions = serialize_capability(capability)?;

            result.push(Pipeline::new(
                id.to_string(),
                id as u32,
                preparsed_pipeline.to_string(),
                file_permissions,
            )?);
        }
        Ok(result)
    }

    /// Serializes the enclave server certificate expiry timepoint to a JSON value,
    /// computing the time when the certificate will expire as a point relative to
    /// the current time.
    fn serialize_enclave_certificate_timepoint(&self) -> Result<Timepoint> {
        info!("Serializing enclave certificate expiry timepoint.");

        let timepoint = self.certificate_expiry;

        Ok(Timepoint::new(
            timepoint.year() as u32,
            timepoint.month() as u8,
            timepoint.day() as u8,
            timepoint.hour() as u8,
            timepoint.minute() as u8,
        )?)
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

    /// Serializes the proxy attestation service certificate (basically reads the
    /// string from the file and returns that
    fn serialize_proxy_service_certificate(&self) -> Result<String> {
        Ok(read_to_string(self.proxy_service_cert.to_str().ok_or(
            anyhow!("Fail to convert proxy_service_cert to str."),
        )?)?)
    }

    fn serialize_execution_strategy(&self) -> Result<ExecutionStrategy> {
        match self.execution_strategy.as_str() {
            "Interpretation" => Ok(ExecutionStrategy::Interpretation),
            "JIT" => Ok(ExecutionStrategy::JIT),
            _otherwise => Err(anyhow!("Could not parse execution strategy argument.")),
        }
    }

    fn serialize_file_hash(&self) -> Result<Vec<FileHash>> {
        info!("Serializing standard streams.");
        let mut result = Vec::new();
        for (file_name, file_path) in self.hashes.iter() {
            let hash = compute_file_hash(file_path)?;
            let file_name = enforce_leading_slash(file_name).into_owned();

            result.push(FileHash::new(file_name, hash));
        }
        Ok(result)
    }
}

/// Checks that the string `strategy` matches either "Interpretation" or "JIT",
/// and if not prints an error message and aborts.
fn check_execution_strategy(strategy: &str) -> Result<()> {
    match strategy {
        "Interpretation" | "JIT" => Ok(()),
        _otherwise => Err(anyhow!("Could not parse execution strategy argument.")),
    }
}

/// Checks that all strings appearing in all vectors in the `capabilities` argument are
/// valid Veracruz capabilities: of the form "[FILE_NAME]:[Right_number]".
fn check_capability(capabilities: &[Vec<String>]) -> Result<()> {
    if !capabilities.iter().all(|v| {
        v.iter().all(|s| {
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
        return Err(anyhow!(
            "Could not parse the capability command line arguments."
        ));
    }
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// JSON serialization.
////////////////////////////////////////////////////////////////////////////////

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

#[inline]
fn serialize_capability(cap_string: &[String]) -> Result<Vec<FileRights>> {
    let mut result = Vec::new();
    for c in cap_string.iter() {
        result.push(serialize_capability_entry(c.as_str())?);
    }
    Ok(result)
}

fn serialize_capability_entry(cap_string: &str) -> Result<FileRights> {
    // common shorthand (r = read, w = write, rw = read + write)
    #[allow(non_snake_case)]
    let READ_RIGHTS = Rights::PATH_OPEN | Rights::FD_READ | Rights::FD_SEEK | Rights::FD_READDIR;

    #[allow(non_snake_case)]
    let WRITE_RIGHTS: Rights = Rights::FD_WRITE
        | Rights::PATH_CREATE_FILE
        | Rights::PATH_FILESTAT_SET_SIZE
        | Rights::FD_SEEK
        | Rights::PATH_OPEN
        | Rights::PATH_CREATE_DIRECTORY;

    #[allow(non_snake_case)]
    let EXECUTE_RIGHTS = Rights::PATH_OPEN | Rights::FD_EXECUTE | Rights::FD_SEEK;

    let mut split = cap_string.split(':');
    let file_name = enforce_leading_slash(
        split
            .next()
            .expect(&format!("Failed to parse {}, empty string", cap_string))
            .trim(),
    )
    .into_owned();
    let string_number = split
        .next()
        .expect(&format!(
            "Failed to parse `{}`, contains no `:`",
            cap_string
        ))
        .trim();

    let re = Regex::new(r"[rwx]+")?;
    let rights = {
        if re.is_match(string_number) {
            let mut rights = Rights::empty();
            if string_number.contains("r") {
                rights = rights | READ_RIGHTS;
            }
            if string_number.contains("w") {
                rights = rights | WRITE_RIGHTS;
            }
            if string_number.contains("x") {
                rights = rights | EXECUTE_RIGHTS;
            }
            rights
        } else {
            // parse raw WASI rights
            let number = string_number
                .parse::<u32>()
                .expect(&format!("Failed to parse {}, not a u64", string_number));
            // check if this is a valid number
            Rights::from_bits(number as u64).expect(&format!(
                "Failed to parse {}, not a u64 representing WASI Right",
                number
            ))
        }
    };

    Ok(FileRights::new(
        file_name,
        u32::try_from(rights.bits()).expect("capability could not fit into u32"),
    ))
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
