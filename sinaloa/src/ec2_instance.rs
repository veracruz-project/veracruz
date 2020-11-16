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
use serde_json::Value;
use err_derive::Error;

pub struct EC2Instance {
    instance_id: String,
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
    #[error(display = "EC2: Unimplemented")]
    Unimplemented,
}

impl EC2Instance {
    pub fn new() -> Result<Self, EC2Error> {
        let ec2_result = Command::new("/usr/local/bin/aws")
            .args(&["ec2", "run-instances", "--image-id", "ami-037dd1d3f98da4d50",
                    "--instance-type", "m5.xlarge", "--enclave-options", "Enabled=true",
                    "--region",  "us-east-1", "--key-name", "Derek's East-1 Key",
                    "--subnet-id=subnet-09dec26c52ea2f0c1", "--security-group-ids", "sg-0db44c78b54499d6d",
                    "--associate-public-ip-address"])
                        .output()
            .map_err(|err| EC2Error::IOError(err))?;
        let ec2_result_stderr = std::str::from_utf8(&ec2_result.stderr)
            .map_err(|err| EC2Error::Utf8Error(err))?;
        println!("ec2_result_stderr:{:?}", ec2_result_stderr);
        let ec2_result_stdout = ec2_result.stdout;
        let ec2_result_text = std::str::from_utf8(&ec2_result_stdout)
            .map_err(|err| EC2Error::Utf8Error(err))?;
        println!("ec2_result_text:{:?}", ec2_result_text);
        std::thread::sleep(std::time::Duration::from_millis(10000));

        let ec2_data: Value = serde_json::from_str(ec2_result_text)
            .map_err(|err| EC2Error::SerdeJsonError(err))?;

        let instance_id: &str = match &ec2_data["Instances"][0]["InstanceId"] {
            Value::String(value) => value,
            _ => return Err(EC2Error::IncorrectJson),
        };

        println!("EC2 Instance ID: {:?}", instance_id);
        Ok(EC2Instance {
            instance_id: instance_id.to_string(),
        })
    }

    pub fn close(&self)-> Result<(), EC2Error> {
        let ec2_result = Command::new("/usr/local/bin/aws")
            .args(&["ec2", "terminate-instances", "--instance-ids", &self.instance_id]).output()
                .map_err(|err| EC2Error::IOError(err))?;
        let ec2_result_stderr = std::str::from_utf8(&ec2_result.stderr)
            .map_err(|err| EC2Error::Utf8Error(err))?;
        println!("ec2_result_stderr:{:?}", ec2_result_stderr);
        let ec2_result_stdout = ec2_result.stdout;
        let ec2_result_text = std::str::from_utf8(&ec2_result_stdout)
            .map_err(|err| EC2Error::Utf8Error(err))?;
        println!("ec2_result_t5ext:{:?}", ec2_result_text);
        return Ok(());
    }

    pub fn upload_file(&self, filename: &str) -> Result<(), EC2Error> {
        Err(EC2Error::Unimplemented)
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
