use std::{ 
    path::PathBuf,
    sync::mpsc::channel,
    time::Duration,
    env::{self, VarError},
    thread,
};
use either::{Left, Right};

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
    let mut path_prefix = env::var("REMOTE_PROGRAM_DIR").unwrap_or("/program/".to_string());
    path_prefix.push_str(filename.as_ref());
    path_prefix
}

/// Add path prefix, `$REMOTE_DATA_DIR` or the default `/input/`, to the program `filename`.
pub fn runtime_data_dir<T: AsRef<str>>(filename: T) -> String {
    let mut path_prefix = env::var("REMOTE_DATA_DIR").unwrap_or("/input/".to_string());
    path_prefix.push_str(filename.as_ref());
    path_prefix
}

/// A wrapper to force tests to panic after a timeout.
///
/// Note this is overrideable with the VERACRUZ_TEST_TIMEOUT environment
/// variable, which provides a timeout in seconds
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

    // based on https://github.com/rust-lang/rfcs/issues/2798#issuecomment-552949300
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
