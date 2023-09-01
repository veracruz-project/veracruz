//! IceCap-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::anyhow;
use err_derive::Error;
use lazy_static::lazy_static;
use log::info;
use policy_utils::policy::Policy;
use proxy_attestation_client;
use signal_hook::{
    consts::SIGINT,
    iterator::{Handle, Signals},
};
use std::{
    convert::TryFrom,
    env,
    error::Error,
    io::{self, Read, Write},
    mem::size_of,
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    string::ToString,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};
use tempfile::{self, TempDir};
use veracruz_server::common::{VeracruzServer, VeracruzServerError};
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

const VERACRUZ_ICECAP_QEMU_BIN_DEFAULT: &[&str] = &["qemu-system-aarch64"];
const VERACRUZ_ICECAP_QEMU_FLAGS_DEFAULT: &[&str] = &[
    "-machine",
    "virt,virtualization=on,gic-version=2",
    "-cpu",
    "cortex-a57",
    "-smp",
    "4",
    "-m",
    "3072",
    "-semihosting-config",
    "enable=on,target=native",
    "-netdev",
    "user,id=netdev0",
    "-serial",
    "mon:stdio",
    "-nographic",
];
const VERACRUZ_ICECAP_QEMU_CONSOLE_FLAGS_DEFAULT: &[&str] = &[
    "-chardev",
    "socket,path={console0_path},server=on,wait=off,id=charconsole0",
    //"-chardev", "socket,server=on,host=localhost,port=1234,id=charconsole0",
    "-device",
    "virtio-serial-device",
    "-device",
    "virtconsole,chardev=charconsole0,id=console0",
];
const VERACRUZ_ICECAP_QEMU_IMAGE_FLAGS_DEFAULT: &[&str] = &["-kernel", "{image_path}"];

lazy_static! {
    /// The Runtime Manager path
    static ref VERACRUZ_ICECAP_QEMU_PATH: String = {
        match env::var("VERACRUZ_ICECAP_QEMU_PATH") {
            Ok(val) => val,
            Err(_) => "/work/veracruz/workspaces/icecap-runtime/build/qemu/disposable/cmake/elfloader/build/elfloader".to_string()
        }
    };
}
/// Class of IceCap-specific errors.
#[derive(Debug, Error)]
pub enum IceCapError {
    #[error(display = "IceCap: Invalid environment variable value: {}", variable)]
    InvalidEnvironmentVariableValue { variable: String },
    #[error(display = "IceCap: Channel error: {}", _0)]
    ChannelError(io::Error),
    #[error(display = "IceCap: Serialization error: {}", _0)]
    SerializationError(#[error(source)] bincode::Error),
    #[error(display = "IceCap: Unexpected response from runtime manager: {:?}", _0)]
    UnexpectedRuntimeManagerResponse(RuntimeManagerResponse),
}

/// IceCap implementation of 'VeracruzServer'
struct IceCapRealm {
    // NOTE the order of these fields matter due to drop ordering
    child: Arc<Mutex<Child>>,
    channel: UnixStream,
    #[allow(dead_code)]
    stdout_handler: JoinHandle<()>,
    #[allow(dead_code)]
    stderr_handler: JoinHandle<()>,
    signal_handle: Handle,
    #[allow(dead_code)]
    signal_handler: JoinHandle<()>,
    #[allow(dead_code)]
    tempdir: TempDir,
}

impl IceCapRealm {
    fn spawn() -> Result<IceCapRealm, VeracruzServerError> {
        fn env_flags(var: &str, default: &[&str]) -> Result<Vec<String>, IceCapError> {
            match env::var(var) {
                Ok(var) => Ok(var.split_whitespace().map(|s| s.to_owned()).collect()),
                Err(env::VarError::NotPresent) => {
                    Ok(default.iter().map(|s| (*s).to_owned()).collect())
                }
                Err(_) => Err(IceCapError::InvalidEnvironmentVariableValue {
                    variable: var.to_owned(),
                }
                .into()),
            }
        }

        // Allow overriding these from environment variables
        let qemu_bin = env_flags("VERACRUZ_ICECAP_QEMU_BIN", VERACRUZ_ICECAP_QEMU_BIN_DEFAULT)
            .map_err(|e| anyhow!(e))?;
        let qemu_flags = env_flags(
            "VERACRUZ_ICECAP_QEMU_FLAGS",
            VERACRUZ_ICECAP_QEMU_FLAGS_DEFAULT,
        )
        .map_err(|e| anyhow!(e))?;
        let qemu_console_flags = env_flags(
            "VERACRUZ_ICECAP_QEMU_CONSOLE_FLAGS",
            VERACRUZ_ICECAP_QEMU_CONSOLE_FLAGS_DEFAULT,
        )
        .map_err(|e| anyhow!(e))?;
        let qemu_image_flags = env_flags(
            "VERACRUZ_ICECAP_QEMU_IMAGE_FLAGS",
            VERACRUZ_ICECAP_QEMU_IMAGE_FLAGS_DEFAULT,
        )
        .map_err(|e| anyhow!(e))?;

        // temporary directory for things
        let tempdir = tempfile::tempdir()?;

        info!("vc-server: using image: {:?}", &*VERACRUZ_ICECAP_QEMU_PATH);

        // create a temporary socket for communication
        let channel_path = tempdir.path().join("console0");
        info!("vc-server: using unix socket: {:?}", channel_path);

        // startup qemu
        let child = Arc::new(Mutex::new(
            Command::new(&qemu_bin[0])
                .args(&qemu_bin[1..])
                .args(&qemu_flags)
                .args(
                    qemu_console_flags
                        .iter()
                        .map(|s| s.replace("{console0_path}", channel_path.to_str().unwrap())),
                )
                .args(
                    qemu_image_flags
                        .iter()
                        .map(|s| s.replace("{image_path}", &*VERACRUZ_ICECAP_QEMU_PATH.as_str())),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| anyhow!(e))?,
        ));

        // forward stderr/stdin via threads, this is necessary to avoid stdio
        // issues under Cargo test
        let stdout_handler = thread::spawn({
            let mut child_stdout = child.lock().unwrap().stdout.take().unwrap();
            move || {
                let err = io::copy(&mut child_stdout, &mut io::stdout());
                eprintln!("vc-server: qemu: stdout closed: {:?}", err);
            }
        });

        let stderr_handler = thread::spawn({
            let mut child_stderr = child.lock().unwrap().stderr.take().unwrap();
            move || {
                let err = io::copy(&mut child_stderr, &mut io::stderr());
                eprintln!("vc-server: qemu: stderr closed: {:?}", err);
            }
        });

        // hookup signal handler so SIGINT will teardown the child process
        let mut signals = Signals::new(&[SIGINT])?;
        let signal_handle = signals.handle();
        let signal_handler = thread::spawn({
            let child = child.clone();
            move || {
                for sig in signals.forever() {
                    eprintln!("vc-server: qemu: Killed by signal: {:?}", sig);
                    child.lock().unwrap().kill().unwrap();
                    signal_hook::low_level::emulate_default_handler(SIGINT).unwrap();
                }
            }
        });

        // connect via socket
        let channel = loop {
            match UnixStream::connect(&channel_path) {
                Ok(channel) => {
                    break channel;
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                // NOTE I don't know why this one happens
                Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(err) => {
                    return Err(VeracruzServerError::Anyhow(anyhow!(
                        IceCapError::ChannelError(err)
                    )));
                }
            };
        };

        Ok(IceCapRealm {
            child,
            stdout_handler,
            stderr_handler,
            signal_handle,
            signal_handler,
            channel,
            tempdir,
        })
    }

    // NOTE close can report errors, but drop can still happen in weird cases
    fn shutdown(self) -> Result<(), IceCapError> {
        info!("vc-server: shutting down");
        self.signal_handle.close();
        self.child
            .lock()
            .unwrap()
            .kill()
            .map_err(|e| IceCapError::ChannelError(e))?;
        Ok(())
    }
}

pub struct VeracruzServerIceCap(Option<IceCapRealm>);

impl VeracruzServerIceCap {
    fn shutdown_isolate(&mut self) -> Result<(), Box<dyn Error>> {
        match self.0.take() {
            Some(realm) => {
                realm.shutdown()?;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl VeracruzServer for VeracruzServerIceCap {
    fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
        let policy: Policy = Policy::from_json(policy_json)?;

        // create the realm
        let mut self_ = Self(Some(IceCapRealm::spawn()?));

        let (device_id, challenge) = proxy_attestation_client::start_proxy_attestation(
            policy.proxy_attestation_server_url(),
        )?;

        let (token, csr) = {
            let attestation = RuntimeManagerRequest::Attestation(challenge, device_id);
            self_.send_buffer(&bincode::serialize(&attestation)?)?;
            let response_buffer = self_.receive_buffer()?;
            let response = bincode::deserialize(&response_buffer[..])?;
            match response {
                RuntimeManagerResponse::AttestationData(token, csr) => (token, csr),
                resp => {
                    return Err(VeracruzServerError::Anyhow(anyhow!(
                        IceCapError::UnexpectedRuntimeManagerResponse(resp)
                    )))
                }
            }
        };

        let cert_chain = {
            let cert_chain = proxy_attestation_client::complete_proxy_attestation_linux(
                policy.proxy_attestation_server_url(),
                &token,
                &csr,
                device_id,
            )
            .map_err(|err| err)?;
            cert_chain
        };

        let initialize = RuntimeManagerRequest::Initialize(policy_json.to_string(), cert_chain);
        self_.send_buffer(&bincode::serialize(&initialize)?)?;
        let response_buffer = self_.receive_buffer()?;
        let response = bincode::deserialize(&response_buffer[..])?;
        match response {
            RuntimeManagerResponse::Status(Status::Success) => (),
            resp => {
                return Err(VeracruzServerError::Anyhow(anyhow!(
                    IceCapError::UnexpectedRuntimeManagerResponse(resp)
                )))
            }
        }

        Ok(self_)
    }

    fn send_buffer(&mut self, buffer: &[u8]) -> Result<(), VeracruzServerError> {
        let header = bincode::serialize(&u32::try_from(buffer.len()).unwrap())?;
        self.0
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?
            .channel
            .write_all(&header)
            .map_err(|e| anyhow!(e))?;
        self.0
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?
            .channel
            .write_all(&buffer)
            .map_err(|e| anyhow!(e))?;
        return Ok(());
    }

    fn receive_buffer(&mut self) -> Result<Vec<u8>, VeracruzServerError> {
        let mut raw_header = [0; size_of::<u32>()];
        self.0
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?
            .channel
            .read_exact(&mut raw_header)
            .map_err(|e| anyhow!(e))?;
        let header = bincode::deserialize::<u32>(&raw_header)?;
        let mut buffer = vec![0; usize::try_from(header).unwrap()];
        self.0
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?
            .channel
            .read_exact(&mut buffer)
            .map_err(|e| anyhow!(e))?;
        return Ok(buffer);
    fn tls_data(
        &mut self,
        session_id: u32,
        input: Vec<u8>,
    ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
        match self.communicate(&RuntimeManagerRequest::SendTlsData(session_id, input))? {
            RuntimeManagerResponse::Status(Status::Success) => (),
            resp => {
                return Err(VeracruzServerError::IceCapError(
                    IceCapError::UnexpectedRuntimeManagerResponse(resp),
                ))
            }
        }

        let mut acc = Vec::new();
        let active = loop {
            if !self.tls_data_needed(session_id)? {
                break true;
            }
            match self.communicate(&RuntimeManagerRequest::GetTlsData(session_id))? {
                RuntimeManagerResponse::TlsData(data, active) => {
                    acc.push(data);
                    if !active {
                        break false;
                    }
                }
                resp => return Err(IceCapError::UnexpectedRuntimeManagerResponse(resp).into()),
            };
        };

        Ok((
            active,
            match acc.len() {
                0 => None,
                _ => Some(acc),
            },
        ))
    }
}

impl Drop for VeracruzServerIceCap {
    fn drop(&mut self) {
        if let Err(err) = self.shutdown_isolate() {
            panic!("Realm failed to shutdown: {}", err)
        }
    }
}
