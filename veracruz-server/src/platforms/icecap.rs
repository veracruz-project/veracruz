//! IceCap-specific material for the Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::common::{VeracruzServerError, VeracruzServerResult};
use err_derive::Error;
use log::error;
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
    fs,
    io::{self, Read, Write},
    mem::size_of,
    os::unix::net::UnixStream,
    process::{Child, Command, Stdio},
    string::ToString,
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};
use tempfile::{self, TempDir};
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

// Include image at compile time
const VERACRUZ_ICECAP_QEMU_IMAGE: &[u8] = include_bytes!(env!("VERACRUZ_ICECAP_QEMU_IMAGE"));

/// Class of IceCap-specific errors.
#[derive(Debug, Error)]
pub enum IceCapError {
    #[error(display = "IceCap: Invalid environment variable value: {}", variable)]
    InvalidEnvironmentVariableValue { variable: String },
    #[error(display = "IceCap: Channel error: {}", _0)]
    ChannelError(io::Error),
    #[error(display = "IceCap: Qemu spawn error: {}", _0)]
    QemuSpawnError(io::Error),
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
        let qemu_bin = env_flags("VERACRUZ_ICECAP_QEMU_BIN", VERACRUZ_ICECAP_QEMU_BIN_DEFAULT)?;
        let qemu_flags = env_flags(
            "VERACRUZ_ICECAP_QEMU_FLAGS",
            VERACRUZ_ICECAP_QEMU_FLAGS_DEFAULT,
        )?;
        let qemu_console_flags = env_flags(
            "VERACRUZ_ICECAP_QEMU_CONSOLE_FLAGS",
            VERACRUZ_ICECAP_QEMU_CONSOLE_FLAGS_DEFAULT,
        )?;
        let qemu_image_flags = env_flags(
            "VERACRUZ_ICECAP_QEMU_IMAGE_FLAGS",
            VERACRUZ_ICECAP_QEMU_IMAGE_FLAGS_DEFAULT,
        )?;

        // temporary directory for things
        let tempdir = tempfile::tempdir()?;

        // write the image to a temporary file, this makes sure our server is
        // idempotent
        let image_path = tempdir.path().join("image");
        fs::write(&image_path, VERACRUZ_ICECAP_QEMU_IMAGE)?;
        println!("vc-server: using image: {:?}", image_path);

        // create a temporary socket for communication
        let channel_path = tempdir.path().join("console0");
        println!("vc-server: using unix socket: {:?}", channel_path);

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
                        .map(|s| s.replace("{image_path}", image_path.to_str().unwrap())),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(IceCapError::QemuSpawnError)?,
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
                    return Err(IceCapError::ChannelError(err).into());
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

    fn communicate(
        &mut self,
        request: &RuntimeManagerRequest,
    ) -> Result<RuntimeManagerResponse, IceCapError> {
        // send request
        let raw_request = bincode::serialize(request)?;
        let raw_header = bincode::serialize(&u32::try_from(raw_request.len()).unwrap())?;
        self.channel
            .write_all(&raw_header)
            .map_err(IceCapError::ChannelError)?;
        self.channel
            .write_all(&raw_request)
            .map_err(IceCapError::ChannelError)?;

        // recv response
        let mut raw_header = [0; size_of::<u32>()];
        self.channel
            .read_exact(&mut raw_header)
            .map_err(IceCapError::ChannelError)?;
        let header = bincode::deserialize::<u32>(&raw_header)?;
        let mut raw_response = vec![0; usize::try_from(header).unwrap()];
        self.channel
            .read_exact(&mut raw_response)
            .map_err(IceCapError::ChannelError)?;
        let response = bincode::deserialize::<RuntimeManagerResponse>(&raw_response)?;

        Ok(response)
    }

    // NOTE close can report errors, but drop can still happen in weird cases
    fn shutdown(self) -> Result<(), IceCapError> {
        println!("vc-server: shutting down");
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
    fn communicate(
        &mut self,
        request: &RuntimeManagerRequest,
    ) -> Result<RuntimeManagerResponse, VeracruzServerError> {
        let response = self
            .0
            .as_mut()
            .ok_or(VeracruzServerError::UninitializedEnclaveError)?
            .communicate(request)?;
        Ok(response)
    }

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

impl VeracruzServerIceCap {
    fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
        let policy: Policy = Policy::from_json(policy_json)?;

        // create the realm
        let mut self_ = Self(Some(IceCapRealm::spawn()?));

        let (device_id, challenge) = proxy_attestation_client::start_proxy_attestation(
            policy.proxy_attestation_server_url(),
        )?;

        let (token, csr) =
            match self_.communicate(&RuntimeManagerRequest::Attestation(challenge, device_id))? {
                RuntimeManagerResponse::AttestationData(token, csr) => (token, csr),
                resp => {
                    return Err(VeracruzServerError::IceCapError(
                        IceCapError::UnexpectedRuntimeManagerResponse(resp),
                    ))
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

        match self_.communicate(&RuntimeManagerRequest::Initialize(
            policy_json.to_string(),
            cert_chain,
        ))? {
            RuntimeManagerResponse::Status(Status::Success) => (),
            resp => {
                return Err(VeracruzServerError::IceCapError(
                    IceCapError::UnexpectedRuntimeManagerResponse(resp),
                ))
            }
        }

        Ok(self_)
    }

    fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError> {
        match self.communicate(&RuntimeManagerRequest::NewTlsSession)? {
            RuntimeManagerResponse::TlsSession(session_id) => Ok(session_id),
            resp => Err(VeracruzServerError::IceCapError(
                IceCapError::UnexpectedRuntimeManagerResponse(resp),
            )),
        }
    }

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
            match self.communicate(&RuntimeManagerRequest::GetTlsData(session_id))? {
                RuntimeManagerResponse::TlsData(data, active) => {
                    if data.len() == 0 {
                        break active;
                    }
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

////////////////////////////////////////////////////////////////////////////////

//xx This should perhaps be called VeracruzEnclave?
pub struct VeracruzServer(
    Arc<(Mutex<Option<VeracruzServerIceCap>>, Condvar)>
);

//xx This should perhaps be called VeracruzConnection?
pub struct VeracruzSession {
    enclave: VeracruzServer,
    session_id: u32,
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl VeracruzServer {
    pub fn new(policy: &str) -> VeracruzServerResult<Self> {
        Ok(VeracruzServer(Arc::new((
            Mutex::new(Some(VeracruzServerIceCap::new(policy)?)),
            Condvar::new(),
        ))))
    }
    pub fn clone(&self) -> Self {
        VeracruzServer(self.0.clone())
    }
    pub fn new_session(&mut self) -> VeracruzServerResult<VeracruzSession> {
        Ok(VeracruzSession {
            enclave: VeracruzServer(self.0.clone()),
            session_id: self
                .0
                .0
                .lock()
                .unwrap()
                .as_mut()
                .ok_or(VeracruzServerError::UninitializedEnclaveError)?
                .new_tls_session()?,
            buffer: Arc::new(Mutex::new(vec![])),
        })
    }
}

impl VeracruzSession {
    pub fn clone(&self) -> Self {
        VeracruzSession {
            enclave: self.enclave.clone(),
            session_id: self.session_id,
            buffer: self.buffer.clone(),
        }
    }
}

impl Read for VeracruzSession {
    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
        if buf.len() == 0 {
            Ok(0)
        } else {
            let mut enclave = self.enclave.0.0.lock().unwrap();
            loop {
                {
                    let mut buffer = self.buffer.lock().unwrap();
                    if enclave.is_none() || buffer.len() > 0 {
                        let n = std::cmp::min(buf.len(), buffer.len());
                        buf[0..n].clone_from_slice(&buffer[0..n]);
                        buffer.drain(0..n);
                        return Ok(n);
                    }
                }
                enclave = self.enclave.0.1.wait(enclave).unwrap();
            }
        }
    }
}

impl Write for VeracruzSession {
    fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        if buf.len() > 0 {
            let mut mb_enclave = self.enclave.0.0.lock().unwrap();
            match mb_enclave.as_mut() {
                None => return Ok(0),
                Some(enclave) => {
                    let (active, output) =
                        match enclave.tls_data(self.session_id, buf.to_vec()) {
                            Ok(x) => x,
                            Err(e) => {
                                error!("tls_data gave error: {}", e);
                                (false, None)
                            }
                        };
                    if !active {
                        eprintln!("session write: !active");
                        mb_enclave.take();
                    }
                    let mut buffer = self.buffer.lock().unwrap();
                    let buffer_len = buffer.len();
                    for x1 in output {
                        for mut x in x1 {
                            buffer.append(&mut x);
                        }
                    }
                    if !active || (buffer_len == 0 && buf.len() > 0) {
                        self.enclave.0.1.notify_all();
                    }
                }
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}
