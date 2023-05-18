//! Implementation of VeracruzServer for AMD SEV-SNP
//!
//! ## Authors
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
    time::Instant,
};
use veracruz_server::{VeracruzServer, VeracruzServerError};
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};
use vsocket::VsockSocket;

pub struct VeracruzServerSev {
    /// A convenience struct for handling VSOCK connections to the enclave
    vsocksocket: VsockSocket,
    //vm_process:  Child,
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
        let handle = Command::new("/work/veracruz/SEVImage/snp-release/usr/local/bin/qemu-system-x86_64")
            .arg("-enable-kvm")
            .arg("-cpu").arg("EPYC-v4")
            .arg("-machine").arg("q35")
            .arg("-smp").arg("4,maxcpus=64")
            .arg("-m").arg("2048M,slots=5,maxmem=30G")
            .arg("-no-reboot")
            .arg("-drive").arg("if=pflash,format=raw,unit=0,file=/work/veracruz/SEVImage/snp-release/usr/local/share/qemu/OVMF_CODE.fd,readonly")
            .arg("-drive").arg("if=pflash,format=raw,unit=1,file=/work/veracruz/SEVImage/sev-guest-dermil01-larger.fd")
            .arg("-drive").arg("file=/work/veracruz/SEVImage/sev-guest-dermil01-larger.img,if=none,id=disk0,format=raw")
            .arg("-device").arg("virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true")
            .arg("-device").arg("scsi-hd,drive=disk0")
            .arg("-machine").arg("memory-encryption=sev0,vmport=off")
            .arg("-object").arg("memory-backend-memfd-private,id=ram1,size=2048M,share=true")
            .arg("-object").arg("sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,discard=none")
            .arg("-machine").arg("memory-backend=ram1,kvm-type=protected")
            .arg("-nographic")
            //.arg("-monitor").arg("pty")
            .arg("-monitor").arg("unix:monitor,server,nowait")
            .arg("-serial").arg("mon:stdio")
            .arg("-device").arg("vhost-vsock-pci,guest-cid=3")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
        let meta = Self {
            //vm_process: handle,
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

    fn send_buffer(&self, buffer: &[u8])-> Result<(), VeracruzServerError> {
        raw_fd::send_buffer(self.vsocksocket.as_raw_fd(), buffer)
            .map_err(|err| {
                VeracruzServerError::Anyhow(anyhow!(err))
            })
    }

    fn receive_buffer(&self) -> Result<Vec<u8>, VeracruzServerError> {
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
        // TODO: Something here
        //self.vm_process.kill()?;
        return Ok(());
    }
}

unsafe impl Send for VeracruzServerSev where Box<VeracruzServerSev>: Send {}
unsafe impl Sync for VeracruzServerSev where Box<VeracruzServerSev>: Send {}