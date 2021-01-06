# Setting up an environment for Veracruz on AWS Nitro Enclaves

Start a standard EC2 instance, with M5.large, x86_64, with a security group that allows port 22 from all IPs, ports 3010 and 9090 from the VPC IPs, with an EBS volume attached (I use 64 GB for that).

Log in to the instance.

Mount the EBS volume (following these instructions: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-using-volumes.html):
```bash
lsblk
sudo file -s /dev/nvme1n1
sudo mkfs -t xfs /dev/nvme1n1
sudo mkdir /ebs_volume
sudo mount /dev/nvme1n1 /ebs_volume/
```

Install some needed packages:
```bash
sudo yum install docker git
sudo yum install openssl11-devel
sudo yum install openssl11
```

Install the AWS CLI tools (source: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html):
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

Following the directions here(https://www.crybit.com/change-default-data-image-directory-docker/), change the location where docker stores images (we do this because the default partition
is too small for the docker images, so we want them stored on the EBS volume):
```bash
sudo systemctl stop docker
sudo mv /var/lib/docker /ebs_volume
sudo ln -s /ebs_volume/docker /var/lib/docker
sudo systemctl start docker
```


Now, get your docker image from wherever (these instructions show it being pulled from AWS ECR - https://docs.aws.amazon.com/AmazonECR/latest/userguide/getting-started-cli.html):
```bash
sudo usermod -a -G docker ec2-user
```
logout
log back in


configure your AWS credentials:
```bash
aws configure
```

authenticate to your registry:
```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 768728991925.dkr.ecr.us-east-1.amazonaws.com
```
pull the image:
```bash
docker pull <IMAGE URI>
```


Clone veracruz source:
```bash
git clone https://github.com/veracruz-project/veracruz.git --recursive
```
Now, run the docker container:
```bash
export VERACRUZ_ROOT=<PATH TO VERACRUZ>
docker run -d -v $VERACRUZ_ROOT:/work/veracruz -v $HOME/.cargo/registry:/home/<USERNAME>/.cargo/registry --name veracruz <IMAGE NAME>
```

Now, start a shell in the container:
```bash
docker exec -u dermil01 -it veracruz bash
```

Install the AWS Nitro Enclaves CLI (source: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html) (TODO: This should be done by the docker build process:
```bash
sudo amazon-linux-extras install aws-nitro-enclaves-cli
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo usermod -aG ne ec2-user
```

Configure nitro enclaves (source: From <https://docs.aws.amazon.com/enclaves/latest/user/enclaves-user.pdf> ).
Edit `/etc/nitro_enclaves/allocator.yaml` and set cpus = 2, memory to 256MB

preparing the build environment inside the container (TODO: This should be done in the container build process):
install the target x86_64-unknown-linux-musl
```bash
rustup target add x86_64-unknown-linux-musl
```

Veracruz needs the ability to start another EC2 instance from your initial EC2 instance. The following instructions set up this ability.

You need to get the subnet that your initial EC2 instance is on.

The id of this subnet should be set in the environment varialbe AWS_SUBNET.

You need to create a security group that allows ports 3010, 9090 for private IP addresses within the subnet.

You probably also want to allow port 22 form all IPs to enable you to SSH into the instance (if you think you'll want to)

The name of this security group should be set in the environment variable AWS_SECURITY_GROUP_ID

You also need to set up an AWSK public/private key pair. You need the private key in a file on your initial EC2 instance. The path to this private key should be set in the environment variable AWS_PRIVATE_KEY_FILENAME.

The name of this key pair (as known by AWS) should be set in the environment variable AWS_KEY_NAME.

The AWS region that you are running on should be set in the environment variable AWS_REGION.

To do this, it is recommended to set the variables in a file called nitro.env as follows:
```bash
export AWS_KEY_NAME="<VALUE>"
export AWS_PRIVATE_KEY_FILENAME="<VALUE>"
export AWS_SUBNET="<VALUE>"
export AWS_REGION="<VALUE>"
export AWS_SECURITY_GROUP_ID="<VALUE>"
```
