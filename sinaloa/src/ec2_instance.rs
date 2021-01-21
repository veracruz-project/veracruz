//! Nitro-Enclave-specific material for Veracruz
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::env;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::process::Command;

use err_derive::Error;
use serde_json::Value;
use ssh2::Session;

use nix::sys::socket::{
    connect, shutdown, socket, AddressFamily, InetAddr, IpAddr, Shutdown, SockAddr, SockFlag,
    SockType,
};
use veracruz_utils;

pub struct EC2Instance {
    pub instance_id: String,
    pub private_ip: String,
    pub socket_port: u16,
    pub socket_fd: Option<RawFd>,
}

#[derive(Debug, Error)]
pub enum EC2Error {
    #[error(display = "EC2: IO Error:{:?}", _0)]
    IOError(std::io::Error),
    #[error(display = "EC2: UTF8 Error:{:?}", _0)]
    Utf8Error(std::str::Utf8Error),
    #[error(display = "EC2: Serde JSON Error:{:?}", _0)]
    SerdeJsonError(serde_json::Error),
    #[error(display = "EC2: Incorrect JSON")]
    IncorrectJson,
    #[error(display = "EC2: SSH2 Error:{:?}", _0)]
    SSH2Error(ssh2::Error),
    #[error(display = "EC2: No Host Key")]
    NoHostKeyError,
    #[error(display = "EC2: Not connected")]
    NotConnectedError,
    #[error(display = "EC2: Veracruz Socket Error:{:?}", _0)]
    VeracruzSocketError(#[error(source)] veracruz_utils::VeracruzSocketError),
    #[error(display = "EC2: Command non-zero status error:{:?}", _0)]
    CommandNonZeroStatus(i32),
    #[error(display = "EC2: Nix error:{:?}", _0)]
    NixError(nix::Error),
    #[error(display = "EC2: CLI error")]
    CLIError,
    #[error(display = "EC2: Unimplemented")]
    Unimplemented,
}

impl EC2Instance {
    pub fn new() -> Result<Self, EC2Error> {
        let aws_key_name =
            env::var("AWS_KEY_NAME").expect("Failed to read AWS_KEY_NAME environment variable.");
        let aws_subnet =
            env::var("AWS_SUBNET").expect("Failed to read AWS_SUBNET environment variable.");
        let aws_region =
            env::var("AWS_REGION").expect("Failed to read AWS_REGION environment variable.");
        let aws_security_group_id = env::var("AWS_SECURITY_GROUP_ID")
            .expect("Failed to read AWS_SECURITY_GROUP_ID environment variable.");

        let subnet_option = format!("--subnet-id={:}", aws_subnet);

        let ec2_result = Command::new("/usr/local/bin/aws")
            .args(&[
                "ec2",
                "run-instances",
                "--image-id",
                "ami-037dd1d3f98da4d50",
                "--instance-type",
                "m5.xlarge",
                "--enclave-options",
                "Enabled=true",
                "--region",
                &aws_region,
                "--key-name",
                &aws_key_name,
                &subnet_option,
                "--security-group-ids",
                &aws_security_group_id,
                "--associate-public-ip-address",
                "--tag-specifications",
                "ResourceType=instance,Tags=[{Key=Veracruz,Value=RootEnclave}]",
            ])
            .output()
            .map_err(|err| {
                println!("EC2Instance::new failed to start ec2 instance:{:?}", err);
                EC2Error::IOError(err)
            })?;
        if !ec2_result.status.success() {
            let ec2_result_text =
                std::str::from_utf8(&ec2_result.stderr).map_err(|err| EC2Error::Utf8Error(err))?;
            println!("ec2 result Stdout:{:}", ec2_result_text);
            return Err(EC2Error::CLIError);
        }

        let ec2_result_text =
            std::str::from_utf8(&ec2_result.stdout).map_err(|err| EC2Error::Utf8Error(err))?;
        let ec2_data: Value =
            serde_json::from_str(ec2_result_text).map_err(|err| EC2Error::SerdeJsonError(err))?;

        let instance_id: &str = match &ec2_data["Instances"][0]["InstanceId"] {
            Value::String(value) => value,
            _ => return Err(EC2Error::IncorrectJson),
        };
        let private_ip: &str = match &ec2_data["Instances"][0]["PrivateIpAddress"] {
            Value::String(value) => value,
            _ => return Err(EC2Error::IncorrectJson),
        };
        println!("EC2Instance instance_id:{:?}", instance_id);
        println!("EC2Instance private_ip:{:?}", private_ip);

        std::thread::sleep(std::time::Duration::from_millis(30000));

        let socket_port: u16 = 9090;

        Ok(EC2Instance {
            instance_id: instance_id.to_string(),
            private_ip: private_ip.to_string(),
            socket_port: socket_port,
            socket_fd: None,
        })
    }

    fn socket_connect(&mut self) -> Result<RawFd, EC2Error> {
        let sockaddr = self.get_private_sockaddr()?;

        let socket_fd = {
            loop {
                match socket(
                    AddressFamily::Inet,
                    SockType::Stream,
                    SockFlag::empty(),
                    None,
                ) {
                    Ok(fd) => break fd,
                    Err(nix::Error::Sys(err)) => match err {
                        nix::errno::Errno::ECONNREFUSED => {
                            println!("EC2Instance::socket failed, ECONNREFUSED, trying again");
                            continue;
                        }
                        _ => panic!(format!("Failed to create socket:{:?}", err)),
                    },
                    Err(err) => panic!(format!("Failed to create socket:{:?}", err)),
                }
            }
        };
        while let Err(_err) = connect(socket_fd, &sockaddr) {}

        self.socket_fd = Some(socket_fd);

        return Ok(socket_fd);
    }

    fn get_private_sockaddr(&self) -> Result<SockAddr, EC2Error> {
        let ip_addr: Vec<u8> = self
            .private_ip
            .split(".")
            .map(|s| s.parse().expect("Parse error"))
            .collect();
        let inet_addr: InetAddr = InetAddr::new(
            IpAddr::new_v4(ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]),
            self.socket_port,
        );
        return Ok(SockAddr::new_inet(inet_addr));
    }

    pub fn close(&mut self) -> Result<(), EC2Error> {
        if let Some(socket_fd) = self.socket_fd.take() {
            match shutdown(socket_fd, Shutdown::Both) {
                Ok(_) => (), // shutdown was successful, continue on your merry way
                Err(err) => {
                    // shutdown was not successful, still attmept to finish the close operation
                    println!("EC2Instance::close failed to shutdown socket({:?}). We're gonna keep going, though", err);
                }
            }
        }
        println!("EC2InstanFce::close attempting to shutdown instance");
        let _ec2_result = Command::new("/usr/local/bin/aws")
            .args(&[
                "ec2",
                "terminate-instances",
                "--instance-ids",
                &self.instance_id,
            ])
            .output()
            .map_err(|err| EC2Error::IOError(err))?;

        println!("EC2Instance::close completed");
        return Ok(());
    }

    pub fn execute_command(&self, command: &str) -> Result<(), EC2Error> {
        let full_ip = format!("{:}:{:}", self.private_ip, 22);
        let tcp = TcpStream::connect(full_ip.clone()).map_err(|err| EC2Error::IOError(err))?;

        let mut session: Session = Session::new().unwrap();
        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|err| EC2Error::SSH2Error(err))?;

        let (key, key_type) = match session.host_key() {
            Some((k, kt)) => (k, kt),
            None => return Err(EC2Error::NoHostKeyError),
        };

        let mut known_hosts = session
            .known_hosts()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        known_hosts
            .add(&full_ip, key, &full_ip, key_type.into())
            .map_err(|err| EC2Error::SSH2Error(err))?;

        let aws_private_key_filename = env::var("AWS_PRIVATE_KEY_FILENAME")
            .expect("Failed to read AWS_PRIVATE_KEY_FILENAME environment variable.");
        let privkey_path: &Path = Path::new(&aws_private_key_filename);
        session
            .userauth_pubkey_file("ec2-user", None, privkey_path, None)
            .map_err(|err| EC2Error::SSH2Error(err))?;
        let mut channel = session
            .channel_session()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        channel
            .exec(command)
            .map_err(|err| EC2Error::SSH2Error(err))?;
        let mut s = String::new();
        channel
            .read_to_string(&mut s)
            .map_err(|err| EC2Error::IOError(err))?;
        channel
            .wait_close()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        let exit_status = channel
            .exit_status()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        if exit_status != 0 {
            println!(
                "EC2Instance::excute_command SSH2 Session returned with non-zero exit-status:{:?}",
                exit_status
            );
            return Err(EC2Error::CommandNonZeroStatus(exit_status));
        }
        Ok(())
    }

    pub fn upload_file(&self, filename: &str, dest: &str) -> Result<(), EC2Error> {
        let file_data: Vec<u8> = self.read_file(filename).map_err(|err| {
            println!(
                "EC2Instance::upload_file failed to read file:{:?}, received error:{:?}",
                filename, err
            );
            err
        })?;
        let full_ip = format!("{:}:{:}", self.private_ip, 22);
        let tcp = TcpStream::connect(full_ip.clone()).map_err(|err| {
            println!(
                "EC2Instance::upload_file Failed to connect to EC2instance:{:?}",
                err
            );
            EC2Error::IOError(err)
        })?;

        let mut session: Session = Session::new().unwrap();
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|err| {
            println!("EC2Instance::upload_file failed handshake:{:?}", err);
            EC2Error::SSH2Error(err)
        })?;

        let (key, key_type) = match session.host_key() {
            Some((k, kt)) => (k, kt),
            None => return Err(EC2Error::NoHostKeyError),
        };

        let mut known_hosts = session
            .known_hosts()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        known_hosts
            .add(&full_ip, key, &full_ip, key_type.into())
            .map_err(|err| EC2Error::SSH2Error(err))?;

        let aws_private_key_filename = env::var("AWS_PRIVATE_KEY_FILENAME")
            .expect("Failed to read AWS_PRIVATE_KEY_FILENAME environment variable.");
        let privkey_path: &Path = Path::new(&aws_private_key_filename);
        session
            .userauth_pubkey_file("ec2-user", None, privkey_path, None)
            .map_err(|err| EC2Error::SSH2Error(err))?;

        let mut remote_file = session
            .scp_send(Path::new(dest), 0o777, file_data.len() as u64, None)
            .map_err(|err| EC2Error::SSH2Error(err))?;
        let _num_written = remote_file.write_all(&file_data).map_err(|err| {
            println!(
                "EC2Instance::upload_file failed to write file data:{:?}",
                err
            );
            EC2Error::IOError(err)
        })?;
        Ok(())
    }

    fn read_file(&self, filename: &str) -> Result<Vec<u8>, EC2Error> {
        let path = Path::new(filename);

        let mut file = File::open(&path).map_err(|err| EC2Error::IOError(err))?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|err| EC2Error::IOError(err))?;

        Ok(buffer)
    }

    pub fn send_buffer(&mut self, buffer: &Vec<u8>) -> Result<(), EC2Error> {
        let socket_fd = match self.socket_fd {
            Some(socket_fd) => socket_fd,
            None => self.socket_connect()?,
        };
        veracruz_utils::send_buffer(socket_fd, buffer).expect("send buffer failed");
        return Ok(());
    }

    pub fn receive_buffer(&mut self) -> Result<Vec<u8>, EC2Error> {
        let socket_fd = match self.socket_fd {
            Some(socket_fd) => socket_fd,
            None => {
                println!("EC2Instance::receive_buffer connecting socket. I don't think this should happen");
                self.socket_connect()?
            }
        };
        let received_buffer =
            veracruz_utils::receive_buffer(socket_fd).expect("Failed to receive buffer");
        return Ok(received_buffer);
    }
}

impl Drop for EC2Instance {
    fn drop(&mut self) {
        match self.close() {
            Err(err) => println!("EC2Instance::drop failed on call to close:{:?}", err),
            _ => (),
        }
    }
}
