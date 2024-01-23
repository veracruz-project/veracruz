//! Implementation of VeracruzServer for AMD SEV-SNP
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result};
use policy_utils::policy::Policy;
use proxy_attestation_client;
use raw_fd;
use std::{
    error::Error,
    os::unix::io::AsRawFd,
    process::{
        Child,
        Command,
        Stdio,
    },
    thread::sleep,
    time::{
        Duration,
        Instant,
    },
};
#[cfg(feature = "debug")]
use std::fs::OpenOptions;
use veracruz_server::{VeracruzServer, VeracruzServerError};
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};
use vsocket::VsockSocket;

pub struct VeracruzServerSev {
    /// A convenience struct for handling VSOCK connections to the enclave
    vsocksocket: VsockSocket,
    vm_process: Child,
}

impl VeracruzServer for VeracruzServerSev {
    fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
        println!("VeracruzServerSev::new started");
        let policy: Policy = Policy::from_json(policy_json)?;
        let (challenge_id, challenge) = proxy_attestation_client::start_proxy_attestation(
            policy.proxy_attestation_server_url(),
        )
        .map_err(|err| {
            eprintln!("Failed to start proxy attestation process. Error produced: {}.",
                err,
            );
            err
        })?;

        let cid: u32 = 3; // TODO: Don't hard-code this
        let port: u32 = 5005;
        let start = Instant::now();
        println!("VeracruzServerSev::new calling qemu");
        let mut command = Command::new("/AMDSEV/snp-release/usr/local/bin/qemu-system-x86_64"); 
        command.arg("-enable-kvm")
            .arg("-cpu").arg("EPYC-v4")
            .arg("-machine").arg("q35")
            .arg("-smp").arg("4,maxcpus=64")
            .arg("-m").arg("2048M,slots=5,maxmem=30G")
            .arg("-no-reboot")
            .arg("-drive").arg("if=pflash,format=raw,unit=0,file=/AMDSEV/snp-release/usr/local/share/qemu/OVMF_CODE.fd,readonly=on")
            .arg("-drive").arg("if=pflash,format=raw,unit=1,file=/AMDSEV/snp-release/usr/local/share/qemu/OVMF_VARS.fd,readonly=on")
            .arg("-device").arg("virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true")
            .arg("-object").arg("sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,discard=none")
            .arg("-machine").arg("memory-encryption=sev0,vmport=off")
            .arg("-object").arg("memory-backend-memfd-private,id=ram1,size=2048M,share=true")
            .arg("-machine").arg("memory-backend=ram1,kvm-type=protected")
            .arg("-nographic")
            .arg("-kernel").arg("/AMDSEV/linux/guest/arch/x86/boot/bzImage")
            .arg("-initrd").arg("/work/veracruz/workspaces/sev-runtime/initramfs_sev")
            .arg("-device").arg("vhost-vsock-pci,guest-cid=3");
        #[cfg(feature = "debug")]
        {
            command = command.arg("-append").arg("\"console=ttyS0\"");
        }
        println!("Running command:{:?}", command);
        let mut stderr_file = Stdio::null();
        let mut stdout_file = Stdio::null();

        #[cfg(feature = "debug")]
        {
            stderr_file = OpenOptions::new().write(true).create(true).open("/work/veracruz/veracruz_qemu_stderr.log").unwrap();
            stdout_file = OpenOptions::new().write(true).create(true).open("/work/veracruz/veracruz_qemu_stdout.log").unwrap();
        }
        let handle = command
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|err| {
                println!("qemu failed to start:{:?}", err);
                err
            })?;
        println!("VeracruzServerSev::new handle:{:?}", handle);
        println!("VeracruzServerSev::new calling VsockSocket::connect");
        let socket = VsockSocket::connect(cid, port)
            .map_err(|err| {
                println!("VsockSocket::connect failed:{:?}", err);
                VeracruzServerError::Anyhow(anyhow!(err))
            })?;
        println!("VeracruzServerSev::now startup took:{} seconds", start.elapsed().as_secs());
        let mut meta = Self {
            vm_process: handle,
            vsocksocket: socket,
        };

        let (attestation_report, csr) = {
            let attestation = RuntimeManagerRequest::Attestation(challenge, challenge_id);
            meta.send_buffer(&bincode::serialize(&attestation)?)?;
            let response = meta.receive_buffer()?;
            match bincode::deserialize(&response[..])? {
                RuntimeManagerResponse::AttestationData(report, csr) => (report, csr),
                response_message => {
                    return Err(VeracruzServerError::InvalidRuntimeManagerResponse(
                        response_message,
                    ))
                }
            }
        };

        let cert_chain = proxy_attestation_client::complete_proxy_attestation_sev(
            policy.proxy_attestation_server_url(),
            &attestation_report,
            &csr,
            challenge_id,
        )?;

        let initialize = RuntimeManagerRequest::Initialize(policy_json.to_string(), cert_chain);
        meta.send_buffer(&bincode::serialize(&initialize)?)?;
        let response = meta.receive_buffer()?;
        let status = match bincode::deserialize(&response[..])? {
            RuntimeManagerResponse::Status(status) => status,
            response_message => return Err(VeracruzServerError::InvalidRuntimeManagerResponse(response_message)),
        };
        match status {
            Status::Success => (),
            _ => return Err(VeracruzServerError::Status(status)),
        }
        println!("VeracruzServerSev::new returning");
        return Ok(meta);
    }

    fn send_buffer(&mut self, buffer: &[u8])-> Result<(), VeracruzServerError> {
        raw_fd::send_buffer(self.vsocksocket.as_raw_fd(), buffer)
            .map_err(|err| {
                VeracruzServerError::Anyhow(anyhow!(err))
            })
    }

    fn receive_buffer(&mut self) -> Result<Vec<u8>, VeracruzServerError> {
        raw_fd::receive_buffer(self.vsocksocket.as_raw_fd())
            .map_err(|err| {
                VeracruzServerError::Anyhow(anyhow!(err))
            })
    }
}

impl Drop for VeracruzServerSev {
    fn drop(&mut self) {
        if let Err(err) = self.shutdown_sev_vm() {
            println!("VeracruzServerSev::drop failed in call to self.shutdown_sev_vm:{:?}", err);
        }
    }
}

impl VeracruzServerSev {
    fn shutdown_sev_vm(&mut self) -> Result<(), Box<dyn Error>> {
        self.vm_process.kill()?;
        sleep(Duration::from_millis(500));
        return Ok(());
    }
}

unsafe impl Send for VeracruzServerSev where Box<VeracruzServerSev>: Send {}
unsafe impl Sync for VeracruzServerSev where Box<VeracruzServerSev>: Send {}