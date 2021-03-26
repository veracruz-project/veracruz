# Setting up an environment for Veracruz on AWS Nitro Enclaves

Note that veracruz relies on an AMI available in us-east-1. We have not test other region.

### VPC

Create a VPC via [this link](https://console.aws.amazon.com/vpc/). 
In the IPv4 CIDR blcok, we are using `192.168.0.0/16`. The rest remains as the default.

### Internet Gateway

Create an internet gateway via [this link](https://console.aws.amazon.com/vpc/). 
Then select the new gateway and attach it to the new VPC in the action menu.

### Subnet
Create a subnet via [this link](https://console.aws.amazon.com/vpc/). 
In the VPC ID, choose the VPC we just created. 
In the available zone choose us-east-1f (we did not test other zone).
In the IPv4 CIDR block, we are using `192.168.32.0/19`
Once we have the new subnet, it is convenient to auto-assign public IPv4 in the action menu. 

### Security Group
Create a new security group attach to the VP we just created.
In the inbound rules,  allows any ssh traffic to port 22 and any TCP to port 3030 and 9090. 
For the latter, we need to pick custom TCP and type in the port number.


### EC2 Instance
Start an EC2 instance.
- Step 1 Choose an Amazon Machine Image (AMI). Use any instance of Amazon Linux on x86.
- Step 2: Choose an Instance Type. Pick M5.xlarge, 
- Step 3: Configure Instance Details. In the network and subnet, choose the VPC and subnet we just created, respectively. Enable Auto-assign Public IP. In the Advanced Details by the end of this page, enable enclave.
- Step 4: Add Storage. Attach an EBS volume (we are using 64GB due to m5.xlarge only have 8GB storage).
- Step 5: Add Tags. Nothing to be done.
- Step 6: Configure Security Group. Select the security group we just created.

### Set up Veracruz in EC2 Instance

Log in to the instance. We are using ssh.

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

Configure nitro enclaves, and test the nitro enclave example application ([source](https://docs.aws.amazon.com/enclaves/latest/user/enclaves-user.pdf) )
Edit `/etc/nitro_enclaves/allocator.yaml` if necessary. We set cpus = 2, memory to 256MB.

### Build or Fetch Veracruz Docker

Following the directions [here](https://www.crybit.com/change-default-data-image-directory-docker/), change the location where docker stores images (we do this because the default partition
is too small for the docker images, so we want them stored on the EBS volume):
```bash
sudo systemctl stop docker
sudo mv /var/lib/docker /ebs_volume
sudo ln -s /ebs_volume/docker /var/lib/docker
sudo systemctl start docker
```
Now, either build or download the docker image from [our repo](https://github.com/veracruz-project/veracruz-docker-image).

If building from the source, run `make nitro TEE=nitro`.
It will start an container `veracruz_nitro`.

If using an existing image,
Set the environment variable `VERACRUZ_ROOT` to the absolute path to the veracruz source code and
Set the environment variable `LOCALIP` to the private AWS IP address of the EC2 instance you are running on.
Start the docker image:
```bash
docker run --privileged -d -v $(abspath $(VERACRUZ_ROOT)):/work/veracruz -v $(HOME)/.cargo/registry/:/usr/local/cargo/registry/ -v /usr/bin:/host/bin -v /usr/share/nitro_enclaves:/usr/share/nitro_enclaves -v /run/nitro_enclaves:/run/nitro_enclaves -v /etc/nitro_enclaves:/etc/nitro_enclaves --device=/dev/vsock:/dev/vsock -v /var/run/docker.sock:/var/run/docker.sock --device=/dev/nitro_enclaves:/dev/nitro_enclaves --env TABASCO_IP_ADDRESS=$(LOCALIP) -p $(LOCALIP):3010:3010/tcp --name veracruz_nitro veracruz_image_nitro
```

### Start Veracruz Docker

Start a shell on the newly launch container:
```bash
docker exec -u root -it veracruz_nitro bash
```

Now, configure your AWS credentials inside the container shell:
```bash
aws configure
```

Veracruz needs the ability to start another EC2 instance from your initial EC2 instance. The following instructions set up this ability.
You need to get the subnet that your initial EC2 instance is on.
The id of this subnet should be set in the environment varialbe AWS_SUBNET.
You need to create a security group that allows ports 3010, 9090 for private IP addresses within the subnet.
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

Now, inside the shell running on the container, execute the following:
```bash
cd /work/veracruz
make nitro-veracruz-server-test
```
You should see 22 tests pass.
