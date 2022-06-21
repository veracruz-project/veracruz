# Setting up an environment for Veracruz on AWS Nitro Enclaves

Start a standard EC2 instance:

* `m5.xlarge` or something else with at least 4 vCPUs
* 64-bit x86
* a security group that allows port 22 from all IPs and ports 3010 and 9090 from the VPC IPs (“My IP”)
* an EBS volume attached (I use 64 GB for that)
* “Nitro Enclave” enabled under “Advanced details”

The instructions that follow assume the default OS, “Amazon Linux”.

Log in to the instance and check:

* There are at least 32 GB available (`df -H .`).
* The device file `/dev/nitro_enclaves` exists.

Install some needed packages:
```bash
sudo yum install -y docker git openssl11 openssl11-devel
```

Install the AWS CLI tools (source: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html):
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

Get Docker working:

* `sudo usermod -a -G docker ec2-user`
* `sudo systemctl start docker`
* Log out and log in again.
* `docker info` should now give lots of info rather than an error

Install the AWS Nitro Enclaves CLI (source: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html):
```bash
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo usermod -aG ne ec2-user
```

Configure Nitro Enclaves (source: https://docs.aws.amazon.com/enclaves/latest/user/enclaves-user.pdf): Edit `/etc/nitro_enclaves/allocator.yaml` and set `cpu_count: 2`, `memory_mib: 512`.

Start the service: `sudo systemctl start nitro-enclaves-allocator.service`

(If `allocator.yaml` is changed later it may be necessary to restart the service.)

Clone veracruz source:
```bash
git clone https://github.com/veracruz-project/veracruz.git --recursive
```

At this point one can save some time by using a Docker image from a registry, or one can build and run a Docker image locally as follows:

```bash
cd veracruz/docker
make nitro-run
make nitro-exec
```

In the Docker image, build and test Veracruz:

```bash
cd veracruz/workspaces
make nitro PROFILE=release
cd nitro-host
make test-server PROFILE=release
make test-client PROFILE=release
make veracruz-test PROFILE=release
```

If a test fails, adding `--nocapture` to the appropriate `$(CARGO_TEST)` command in `nitro-host/Makefile` may reveal a helpful error message.
