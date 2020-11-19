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

use crate::sinaloa::SinaloaError;
use std::process::Command;
use std::net::TcpStream;
use serde_json::Value;
use err_derive::Error;
use std::path::Path;
use ssh2::{ Session};
use std::io::Write;
use std::io::Read;
use std::fs::File;
use veracruz_utils;

pub struct EC2Instance {
    pub instance_id: String,
    pub private_ip: String,
    pub socket_port: u32,
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
    #[error(display = "EC2: SSH2 ERror:{:?}", _0)]
    SSH2Error(ssh2::Error),
    #[error(display = "EC2: No Host Key")]
    NoHostKeyError,
    #[error(display = "EC2: Veracruz Socket Error:{:?}", _0)]
    VeracruzSocketError(#[error(source)] veracruz_utils::VeracruzSocketError),
    #[error(display = "EC2: Unimplemented")]
    Unimplemented,
}

const AWS_KEY_NAME: &str = "NitroNode2NodeKey";
const PRIVATE_KEY_FILENAME: &str = "/home/ec2-user/.ssh/nitro_node_2_node.pem";

//const SECURITY_GROUP_ID: &str = "sg-0db44c78b54499d6d";
const SECURITY_GROUP_ID: &str = "sg-04983d4be43f84550";

impl EC2Instance {
    pub fn new() -> Result<Self, EC2Error> {
        let ec2_result = Command::new("/usr/local/bin/aws")
            .args(&["ec2", "run-instances", "--image-id", "ami-037dd1d3f98da4d50",
                    "--instance-type", "m5.xlarge", "--enclave-options", "Enabled=true",
                    "--region",  "us-east-1", "--key-name", AWS_KEY_NAME,
                    "--subnet-id=subnet-09dec26c52ea2f0c1", "--security-group-ids", SECURITY_GROUP_ID,
                    "--associate-public-ip-address"])
                        .output()
            .map_err(|err| EC2Error::IOError(err))?;
        let ec2_result_stderr = std::str::from_utf8(&ec2_result.stderr)
            .map_err(|err| EC2Error::Utf8Error(err))?;
        println!("ec2_result_stderr:{:?}", ec2_result_stderr);
        let ec2_result_stdout = ec2_result.stdout;
        let ec2_result_text = std::str::from_utf8(&ec2_result_stdout)
            .map_err(|err| EC2Error::Utf8Error(err))?;

        let ec2_data: Value = serde_json::from_str(ec2_result_text)
            .map_err(|err| EC2Error::SerdeJsonError(err))?;

        let instance_id: &str = match &ec2_data["Instances"][0]["InstanceId"] {
            Value::String(value) => value,
            _ => return Err(EC2Error::IncorrectJson),
        };
        let private_ip: &str = match &ec2_data["Instances"][0]["PrivateIpAddress"] {
            Value::String(value) => value,
            _ => return Err(EC2Error::IncorrectJson),
        };

        println!("EC2 Instance ID: {:?}", instance_id);

        std::thread::sleep(std::time::Duration::from_millis(30000));

        Ok(EC2Instance {
            instance_id: instance_id.to_string(),
            private_ip: private_ip.to_string(),
            socket_port: 9090,
        })
    }

    pub fn close(&self)-> Result<(), EC2Error> {
        println!("EC2Instance::close attempting to shutdown instance");
        let ec2_result = Command::new("/usr/local/bin/aws")
            .args(&["ec2", "terminate-instances", "--instance-ids", &self.instance_id]).output()
                .map_err(|err| EC2Error::IOError(err))?;
        let ec2_result_stderr = std::str::from_utf8(&ec2_result.stderr)
            .map_err(|err| EC2Error::Utf8Error(err))?;
        let ec2_result_stdout = ec2_result.stdout;
        let ec2_result_text = std::str::from_utf8(&ec2_result_stdout)
            .map_err(|err| EC2Error::Utf8Error(err))?;
        println!("EC2Instance::close succeeded");
        return Ok(());
    }

    pub fn execute_command(&self, command: &str) -> Result<(), EC2Error> {
        let full_ip = format!("{:}:{:}", self.private_ip, 22);
        println!("EC2Instance::execute_command attempting to connect to {:?}", full_ip);
        let tcp = TcpStream::connect(full_ip.clone())
            .map_err(|err| EC2Error::IOError(err))?;

        let mut session: Session = Session::new().unwrap();
        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|err| EC2Error::SSH2Error(err))?;

        let (key, key_type) = match session.host_key() {
            Some((k, kt)) => (k, kt),
            None => return Err(EC2Error::NoHostKeyError),
        };

        let mut known_hosts = session.known_hosts()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        known_hosts.add(&full_ip, key, &full_ip, key_type.into())
            .map_err(|err| EC2Error::SSH2Error(err));

        let privkey_path: &Path = Path::new(PRIVATE_KEY_FILENAME);
        session.userauth_pubkey_file("ec2-user",
            None,
            privkey_path,
            None
            )
            .map_err(|err| EC2Error::SSH2Error(err))?;
        let mut channel = session.channel_session()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        channel.exec(command)
            .map_err(|err| EC2Error::SSH2Error(err))?;
        let mut s = String::new();
        channel.read_to_string(&mut s)
            .map_err(|err| EC2Error::IOError(err))?;
        println!("Command result:{:?}", s);
        channel.wait_close();
        let exit_status = channel.exit_status()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        println!("channel exit status:{:?}", exit_status);
        Ok(())
    }

    pub fn upload_file(&self, filename: &str, dest: &str) -> Result<(), EC2Error> {

        let file_data: Vec<u8> = self.read_file(filename)?;
        let full_ip = format!("{:}:{:}", self.private_ip, 22);
        println!("EC2Instance::upload_file attempting to connect to {:?}", full_ip);
        let tcp = TcpStream::connect(full_ip.clone())
            .map_err(|err| EC2Error::IOError(err))?;

        let mut session: Session = Session::new().unwrap();
        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|err| EC2Error::SSH2Error(err))?;

        let (key, key_type) = match session.host_key() {
            Some((k, kt)) => (k, kt),
            None => return Err(EC2Error::NoHostKeyError),
        };

        let mut known_hosts = session.known_hosts()
            .map_err(|err| EC2Error::SSH2Error(err))?;
        known_hosts.add(&full_ip, key, &full_ip, key_type.into())
            .map_err(|err| EC2Error::SSH2Error(err));

        let privkey_path: &Path = Path::new(PRIVATE_KEY_FILENAME);
        session.userauth_pubkey_file("ec2-user",
            None,
            privkey_path,
            None
            )
            .map_err(|err| EC2Error::SSH2Error(err))?;

        println!("EC2Instance::upload_file attempting to upload {:?} bytes", file_data.len());
        let mut remote_file = session.scp_send(Path::new(dest), 0o777, file_data.len() as u64, None)
            .map_err(|err| EC2Error::SSH2Error(err))?;
        let num_written = remote_file.write_all(&file_data)
            .map_err(|err| EC2Error::IOError(err))?;
        println!("EC2Instance::upload_file wrote {:?} bytes", num_written);
        println!("EC2Instance::upload_file done");
        Ok(())
    }

    fn read_file(&self, filename: &str) -> Result<Vec<u8>, EC2Error> {
        let path = Path::new(filename);

        let mut file = File::open(&path)
            .map_err(|err| EC2Error::IOError(err))?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|err| EC2Error::IOError(err))?;

        Ok(buffer)
    }

    pub fn send_buffer(&self, buffer: &Vec<u8>) -> Result<(), EC2Error> {
        println!("ec2_instance:send_buffer started");
        let instance_url: String = format!("{:}:{:}", self.private_ip, self.socket_port);
        let mut stream = TcpStream::connect(instance_url)
            .map_err(|err| EC2Error::IOError(err))?;
        stream.write(buffer)
            .map_err(|err| EC2Error::IOError(err))?;
        Ok(())
    }

    pub fn receive_buffer(&self) -> Result<Vec<u8>, EC2Error> {
        println!("ec2_instance::receive_buffer started");
        let instance_url: String = format!("{:}:{:}", self.private_ip, self.socket_port);
        let mut stream = TcpStream::connect(instance_url)
            .map_err(|err| EC2Error::IOError(err))?;
        let mut buffer: Vec<u8> = Vec::new();
        stream.read(&mut buffer)
            .map_err(|err| EC2Error::IOError(err))?;
        Ok(buffer)
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
