//! Veracruz Client command-line interface
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use either::Either;
use structopt::StructOpt;
use std::{
    cell::RefCell,
    cell::RefMut,
    fs,
    io,
    io::Read,
    io::Write,
    path,
    process,
    time::Duration,
};
use veracruz_client::{
    VeracruzAdminClient,
    VeracruzClient,
};
use veracruz_utils::policy::{
    error::PolicyError,
    parsers,
    policy::Policy,
};


/// A bit of extra parsing to allow omitting addr/port
fn parse_bind_addr(s: &str) -> String {
    // Rust's SocketAddr parser requires an explicit address/port, add 0.0.0.0
    // if omitted, this lets ':3010' be used to specify only the port
    if s.starts_with(':') {
        format!("0.0.0.0{}", s)
    } else if s.ends_with(':') {
        format!("{}0", s)
    } else {
        s.to_string()
    }
}

/// Parse either path or a url
///
/// This attempts to open the file, falling back to url parsing if this
/// doesn't work
fn parse_policy_path_or_bind_addr(s: &std::ffi::OsStr) -> Either<path::PathBuf, String> {
    if fs::metadata(s).ok().map(|m| m.is_file()).unwrap_or(false) {
        Either::Left(path::PathBuf::from(s))
    } else {
        Either::Right(parse_bind_addr(&s.to_string_lossy()))
    }
}

#[derive(Debug, StructOpt)]
#[structopt(rename_all="kebab")]
struct Opt {
    /// Optional path to the policy file
    ///
    /// Or a URL, this can actually take both a policy file or a URL to the
    /// server since you usually only need to provide one of those.
    ///
    /// This tries to open the policy file, and if that fails, falls back to
    /// treating this as a URL. If this isn't desired, you can specify either
    /// the policy file or the URL with the explicit --policy and --url flags.
    ///
    #[structopt(
        name="policy_path",
        parse(from_os_str=parse_policy_path_or_bind_addr)
    )]
    policy_path_or_url: Option<Either<path::PathBuf, String>>,

    /// Optional URL of server to connect to
    ///
    /// If not provided, the URL in the policy file will be used
    ///
    #[structopt(long, parse(from_str=parse_bind_addr))]
    url: Option<String>,

    /// Optional path to policy file
    ///
    /// If not provided, the client will be limited to administrative commands
    /// such as querying what enclaves are running
    ///
    #[structopt(long="policy", parse(from_os_str))]
    policy_path: Option<path::PathBuf>,

    /// Request quiet operation
    ///
    /// Normally the state of the operation is printed to stderr so as not
    /// to mingle with stdout which may be piped from a result in the enclave,
    /// but this can turn that off.
    ///
    /// Note that unrecoverable errors will still be printed to stderr.
    #[structopt(short, long)]
    quiet: bool,

    /// Path to client certificate file
    #[structopt(short, long, parse(from_os_str))]
    identity: Option<path::PathBuf>,

    /// Path to client key file
    #[structopt(short, long, parse(from_os_str))]
    key: Option<path::PathBuf>,

    /// Request the server to Setup a new enclave with the provided policy
    #[structopt(long)]
    setup: Option<Option<path::PathBuf>>,

    /// Request the server to teardown a running enclave
    #[structopt(long)]
    teardown: bool,

    /// Query a list of running enclaves
    #[structopt(long)]
    query_list: bool,

    /// Query the policy governing the enclave on the server
    ///
    /// The policy will be written to the provided path. Also
    /// accepts "-" to write to stdout.
    ///
    #[structopt(long)]
    query_policy: Option<path::PathBuf>,

    /// Specify optional program files to upload
    ///
    /// This can be in the form of "--program name", or in the form
    /// of "--program enclave_name=path" if you want to supply the file
    /// as a different name in the enclave. Multiple --program flags
    /// or a comma-separated list of files may be provided. Also
    /// accepts "-" to read from stdin.
    ///
    /// Note: This requires "PiProvider" permissions in the
    /// policy file.
    ///
    #[structopt(
        short, long, multiple=true, number_of_values=1,
        visible_alias="programs",
        parse(try_from_os_str=parsers::parse_renamable_paths)
    )]
    program: Vec<Vec<(String, path::PathBuf)>>,

    /// Specify optional data files to upload
    ///
    /// This can be in the form of "--data name", or in the form
    /// of "--data enclave_name=path" if you want to supply the file
    /// as a different name in the enclave. Multiple --data flags
    /// or a comma-separated list of files may be provided. Also
    /// accepts "-" to read from stdin.
    ///
    /// Note: This requires "DataProvider" permissions in the
    /// policy file.
    ///
    #[structopt(
        short, long, multiple=true, number_of_values=1,
        visible_alias="datas",
        parse(try_from_os_str=parsers::parse_renamable_paths)
    )]
    data: Vec<Vec<(String, path::PathBuf)>>,

    /// Specify optional output files to store results. If not provided
    /// the results will not be fetched.
    ///
    /// This can be in the form of "--result name", or in the form
    /// of "--result enclave_name=path" if you want to fetch with a
    /// different name in the enclave. Multiple --result flags
    /// or a comma-separated list of files may be provided. Also
    /// accepts "-" to write to stdout.
    ///
    /// If --no-shutdown is not provided, Veracruz Client will request a shutdown
    /// from the Sinaloa server after recieving the results.
    ///
    /// Note: This requires "ResultReader" permissions in the
    /// policy file.
    ///
    #[structopt(
        short, long, multiple=true, number_of_values=1,
        visible_alias="outputs",
        visible_alias="result",
        visible_alias="results",
        parse(try_from_os_str=parsers::parse_renamable_paths)
    )]
    output: Vec<Vec<(String, path::PathBuf)>>,

    /// Signal that we aren't done with the computation even if we request
    /// data.
    ///
    /// By default this client signals that we are done with the computation
    /// if we read the result, since this is the most common case. This flag
    /// overrides that, allowing multiple reads by the same identity.
    ///
    #[structopt(short, long)]
    not_done: bool,

    /// Signal that we are done without requesting data.
    ///
    /// Note: This requires "ResultReader" permissions in the
    /// policy file.
    #[structopt(long)]
    done: bool,
}

/// A macro to make printing a bit easier with support for --quiet
macro_rules! qprintln {
    ($opt:expr) => (if !$opt.quiet { eprintln!(); });
    ($opt:expr, $($arg:tt)*) => (if !$opt.quiet { eprintln!($($arg)*); });
}

/// Format Durations as human readable timestamps
fn format_uptime(t: Duration) -> String {
    let t = t.as_secs();
    format!("{}d {}h {}m {}s",
        t / (24*60*60),
        (t % (24*60*60)) / (60*60),
        (t % (60*60)) / 60,
        t % 60
    )
}


/// Entry point
fn main() {
    // parse args
    let opt = Opt::from_args();

    // setup logger
    env_logger::init();

    // is policy_path provided? is url?
    let policy_path = match (opt.policy_path_or_url.as_ref(), opt.policy_path.as_ref()) {
        (Some(Either::Left(policy_path)), None) => Some(policy_path),
        (_, Some(policy_path))                  => Some(policy_path),
        _                                       => None,
    };

    let url = match (&opt.policy_path_or_url, &opt.url) {
        (Some(Either::Right(url)), None) => Some(url),
        (_, Some(url))                   => Some(url),
        _                                => None,
    };

    // load policy
    let policy = match policy_path {
        Some(policy_path) => {
            let (policy_json, policy) = match
                fs::read_to_string(&policy_path)
                    .map_err(|err| PolicyError::from(err))
                    .and_then(|policy_json| {
                        Policy::from_json(&policy_json)
                            .map(|policy| (policy_json, policy))
                    })
            {
                Ok((policy_json, policy)) => (policy_json, policy),
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            };
            qprintln!(opt, "Loaded policy {}", policy_path.to_string_lossy());
            qprintln!(opt, "  (with hash) {}", policy.policy_hash().unwrap_or("???"));
            Some((policy_json, policy))
        }
        None => None,
    };

    // figure out the URL to connect to
    let url = match (url.as_ref(), policy.as_ref()) {
        (Some(url), _) => url,
        (None, Some((_, policy))) => policy.veracruz_server_url(),
        (None, None) => {
            eprintln!("Requires either a policy_path or url (see --help?)");
            process::exit(2);
        }
    };
    qprintln!(opt, "Connecting to {}", url);

    // Lazily create a Veracruz Admin Client instance when needed
    let lazy_admin_client: RefCell<Option<VeracruzAdminClient>> = RefCell::new(None);
    let admin_client = || -> RefMut<'_, VeracruzAdminClient> {
        RefMut::map(
            lazy_admin_client.borrow_mut(),
            |ref_| {
                ref_.get_or_insert_with(|| {
                    VeracruzAdminClient::new(&url)
                })
            }
        )
    };

    // Lazily create a Veracruz Client instance when needed
    let lazy_veracruz_client: RefCell<Option<VeracruzClient>> = RefCell::new(None);
    let veracruz_client = || -> RefMut<'_, VeracruzClient> {
        RefMut::map(
            lazy_veracruz_client.borrow_mut(),
            |ref_| {
                ref_.get_or_insert_with(|| {
                    let policy = match &policy {
                        Some((_, policy)) => policy,
                        None => {
                            eprintln!("Requires policy_path to interact with enclave");
                            process::exit(1);
                        }
                    };

                    let (identity, key) = match (&opt.identity, &opt.key) {
                        (Some(identity), Some(key)) => (identity, key),
                        _ => {
                            eprintln!("Requires identity and key to interact with enclave");
                            process::exit(1);
                        }
                    };

                    match VeracruzClient::with_url_policy_and_hash(
                        &url,
                        identity,
                        key,
                        policy.clone(),
                        policy.policy_hash().unwrap().to_string(),
                    ) {
                        Ok(veracruz_client) => veracruz_client,
                        Err(err) => {
                            eprintln!("{}", err);
                            process::exit(1);
                        }
                    }
                })
            }
        )
    };


    //// Here's where we actually do things ////

    let mut did_something = false;

    // setup enclave?
    if let Some(yet_another_policy_path) = &opt.setup {
        let mut admin_client = admin_client();

        qprintln!(opt, "Setting up enclave");
        did_something = true;

        let policy_json = match (yet_another_policy_path, &policy) {
            (Some(_), Some(_)) => {
                eprintln!("Multiple policies provided?");
                process::exit(1);
            }
            (Some(policy_path), _) => {
                match fs::read_to_string(&policy_path) {
                    Ok(policy_json) => policy_json,
                    Err(err) => {
                        eprintln!("{}", err);
                        process::exit(1);
                    }
                }
            }
            (None, Some((policy_json, _))) => {
                policy_json.clone()
            }
            (None, None) => {
                eprintln!("Setting up an enclave requires a policy");
                process::exit(1);
            }
        };

        match admin_client.enclave_setup(&policy_json) {
            Ok(()) => {},
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    // query for a list of enclaves?
    if opt.query_list {
        let admin_client = admin_client();

        qprintln!(opt, "Querying list of enclaves");
        did_something = true;

        match admin_client.enclave_list() {
            Ok(list) => {
                println!("{:>5} {:<64}  {:<7}", "id", "policy hash", "uptime");
                for enclave in list {
                    println!("{:>5} {:<64}  {}",
                        enclave.id,
                        enclave.policy_hash,
                        format_uptime(enclave.uptime),
                    );
                }
            }
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    // query for an enclave's policy
    if let Some(policy_path) = &opt.query_policy {
        let admin_client = admin_client();

        qprintln!(opt, "Querying policy into {}",
            match policy_path.to_string_lossy().as_ref() {
                "-" => "<stdout>",
                path => path,
            });
        did_something = true;

        match admin_client.enclave_policy() {
            Ok(policy) if policy_path.to_string_lossy() == "-" => {
                match io::stdout().write_all(policy.as_bytes()) {
                    Ok(()) => {},
                    Err(err) => {
                        eprintln!("{}", err);
                        process::exit(1);
                    }
                }
            }
            Ok(policy) => {
                match fs::write(policy_path, policy) {
                    Ok(()) => {},
                    Err(err) => {
                        eprintln!("{}", err);
                        process::exit(1);
                    }
                }
            }
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    // send program(s)?
    for (program_name, program_path) in opt.program.iter().flatten() {
        let mut veracruz_client = veracruz_client();

        qprintln!(opt, "Submitting <enclave>/{} from {}",
            program_name,
            match program_path.to_string_lossy().as_ref() {
                "-" => "<stdout>",
                path => path,
            });
        did_something = true;

        let program_data = if program_path == &path::PathBuf::from("-") {
            let mut program_data = Vec::new();
            match io::stdin().read_to_end(&mut program_data) {
                Ok(_) => program_data,
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::read(program_path) {
                Ok(program_data) => program_data,
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        };

        match veracruz_client.send_program(&program_name, &program_data) {
            Ok(()) => {}
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    // send data(s)?
    for (data_name, data_path) in opt.data.iter().flatten() {
        let mut veracruz_client = veracruz_client();

        qprintln!(opt, "Submitting <enclave>/{} from {}",
            data_name,
            match data_path.to_string_lossy().as_ref() {
                "-" => "<stdout>",
                path => path,
            });
        did_something = true;

        let data_data = if data_path == &path::PathBuf::from("-") {
            let mut data_data = Vec::new();
            match io::stdin().read_to_end(&mut data_data) {
                Ok(_) => data_data,
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::read(data_path) {
                Ok(data_data) => data_data,
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        };

        match veracruz_client.send_data(data_name, &data_data) {
            Ok(()) => {}
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    // fetch result(s)?
    // TODO why does results take the path to the _binary_? can this
    // API be better?
    for (output_name, output_path) in opt.output.iter().flatten() {
        let mut veracruz_client = veracruz_client();

        qprintln!(opt, "Reading <enclave>/{} into {}",
            output_name,
            match output_path.to_string_lossy().as_ref() {
                "-" => "<stdout>",
                path => path,
            });
        did_something = true;

        let results = match veracruz_client.get_results(output_name) {
            Ok(results) => results,
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        };

        if output_path == &path::PathBuf::from("-") {
            match io::stdout().write_all(&results) {
                Ok(()) => {},
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        } else {
            match fs::write(output_path, results) {
                Ok(()) => {},
                Err(err) => {
                    eprintln!("{}", err);
                    process::exit(1);
                }
            }
        }
    }

    // done?
    if (!opt.output.is_empty() && !opt.not_done) || opt.done {
        let mut veracruz_client = veracruz_client();

        // don't bother to print this unless explicitly requested
        if opt.done {
            qprintln!(opt, "Signalling done-ness");
        }
        did_something = true;

        match veracruz_client.signal_done() {
            Ok(()) => {}
            Err(err) => {
                eprintln!("{}", err);
                process::exit(1);
            }
        }
    }

    // teardown enclave?
    //
    // note the order matters significantly here, if we are interacting with
    // the enclave it doesn't make sense to tear down the enclave first
    //
    if opt.teardown {
        let mut admin_client = admin_client();

        qprintln!(opt, "Tearing down enclave");
        did_something = true;

        match admin_client.enclave_teardown() {
            Ok(()) => {},
            Err(err) => {
                println!("{}", err);
                process::exit(1);
            }
        }
    }

    if !did_something {
        qprintln!(opt, "Nothing to do");
        process::exit(2);
    }
}
