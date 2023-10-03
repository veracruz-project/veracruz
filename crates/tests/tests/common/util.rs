use either::{Left, Right};
use policy_utils::policy::Policy;
use std::{
    env::{self, VarError},
    io::Read,
    path::{Path, PathBuf},
    sync::mpsc::channel,
    thread,
    time::Duration,
};
use veracruz_utils::sha256::sha256;

/// Add the policy directory, reading from environment variable `$VERACRUZ_POLICY_DIR` or using the
/// default `test-collateral`.
pub fn policy_dir<T: AsRef<str>>(filename: T) -> PathBuf {
    PathBuf::from(env::var("VERACRUZ_POLICY_DIR").unwrap_or("../test-collateral".to_string()))
        .join(filename.as_ref())
}

/// Add the certificate and key directory, reading from environment variable `$VERACRUZ_TRUST_DIR`
/// or using the default `test-collateral`.
pub fn cert_key_dir<T: AsRef<str>>(filename: T) -> PathBuf {
    PathBuf::from(env::var("VERACRUZ_TRUST_DIR").unwrap_or("../test-collateral".to_string()))
        .join(filename.as_ref())
}

/// Add the program directory, reading from environment variable `$VERACRUZ_PROGRAM_DIR`
/// or using the default `test-collateral`.
pub fn program_dir<T: AsRef<str>>(filename: T) -> PathBuf {
    PathBuf::from(env::var("VERACRUZ_PROGRAM_DIR").unwrap_or("../test-collateral".to_string()))
        .join(filename.as_ref())
}

/// Add the data directory, reading from environment variable `$VERACRUZ_DATA_DIR`
/// or using the default `test-collateral`.
pub fn data_dir<T: AsRef<str>>(filename: T) -> PathBuf {
    PathBuf::from(env::var("VERACRUZ_DATA_DIR").unwrap_or("../test-collateral".to_string()))
        .join(filename.as_ref())
}

/// Add path prefix, `$REMOTE_PROGRAM_DIR` or the default `/program/`, to the program `filename`.
pub fn runtime_program_dir<T: AsRef<str>>(filename: T) -> String {
    let mut path_prefix = env::var("REMOTE_PROGRAM_DIR").unwrap_or("./program/".to_string());
    path_prefix.push_str(filename.as_ref());
    path_prefix
}

/// Add path prefix, `$REMOTE_DATA_DIR` or the default `/input/`, to the program `filename`.
pub fn runtime_data_dir<T: AsRef<str>>(filename: T) -> String {
    let mut path_prefix = env::var("REMOTE_DATA_DIR").unwrap_or("./input/".to_string());
    path_prefix.push_str(filename.as_ref());
    path_prefix
}

/// A wrapper to force tests to panic after a timeout.
///
/// Note this is overrideable with the VERACRUZ_TEST_TIMEOUT environment
/// variable, which provides a timeout in seconds
#[allow(dead_code)] // FIXME
pub fn timeout<R: Send + 'static, F: (FnOnce() -> R) + Send + 'static>(
    timeout: Duration,
    f: F,
) -> R {
    let timeout = match env::var("VERACRUZ_TEST_TIMEOUT")
        .map_err(Left)
        .and_then(|timeout| timeout.parse::<u64>().map_err(Right))
    {
        Ok(val) => Duration::from_secs(val),
        Err(Left(VarError::NotPresent)) => timeout,
        Err(err) => panic!("Couldn't parse VERACRUZ_TEST_TIMEOUT: {:?}", err),
    };

    let (done_tx, done_rx) = channel();
    let thread = thread::spawn(move || {
        let r = f();
        done_tx.send(()).unwrap();
        r
    });

    match done_rx.recv_timeout(timeout) {
        Ok(_) => thread.join().expect("thread panicked"),
        Err(_) => panic!(
            "timeout after {:?}, specify VERACRUZ_TEST_TIMEOUT to override",
            timeout
        ),
    }
}

/// Auxiliary function: read policy file
pub fn read_policy<T: AsRef<Path>>(fname: T) -> anyhow::Result<(Policy, String, String)> {
    let fname = fname.as_ref();
    let policy_json = std::fs::read_to_string(fname)?;

    let policy_hash = sha256(policy_json.as_bytes());
    let policy_hash_str = hex::encode(&policy_hash);
    let policy = Policy::from_json(policy_json.as_ref())?;
    Ok((policy, policy_json.to_string(), policy_hash_str))
}

pub fn read_local_file<T: AsRef<Path>>(filename: T) -> anyhow::Result<Vec<u8>> {
    let mut data_file = std::fs::File::open(filename.as_ref())?;
    let mut data_buffer = std::vec::Vec::new();
    data_file.read_to_end(&mut data_buffer)?;
    Ok(data_buffer)
}
