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

Configure nitro enclaves (source: From <https://docs.aws.amazon.com/enclaves/latest/user/enclaves-user.pdf> )
Edit `/etc/nitro_enclaves/allocator.yaml` and set cpus = 2, memory to 256MB

Following the directions here(https://www.crybit.com/change-default-data-image-directory-docker/), change the location where docker stores images (we do this because the default partition
is too small for the docker images, so we want them stored on the EBS volume):
```bash
sudo systemctl stop docker
sudo mv /var/lib/docker /ebs_volume
sudo ln -s /ebs_volume/docker /var/lib/docker
sudo systemctl start docker
```
Now, either build or download the docker image from our repo (https://github.com/veracruz-project/veracruz-docker-image)

Set the environment variable `VERACRUZ_ROOT` to the absolute path to the veracruz source code.

Set the environment variable `LOCALIP` to the private AWS IP address of the EC2 instance you are running on.
Start the docker image:
```bash
docker run --privileged -d -v $(abspath $(VERACRUZ_ROOT)):/work/veracruz -v $(HOME)/.cargo/registry/:/usr/local/cargo/registry/ -v /usr/bin:/host/bin -v /usr/share/nitro_enclaves:/usr/share/nitro_enclaves -v /run/nitro_enclaves:/run/nitro_enclaves -v /etc/nitro_enclaves:/etc/nitro_enclaves --device=/dev/vsock:/dev/vsock -v /var/run/docker.sock:/var/run/docker.sock --device=/dev/nitro_enclaves:/dev/nitro_enclaves --env TABASCO_IP_ADDRESS=$(LOCALIP) -p $(LOCALIP):3010:3010/tcp --name veracruz_nitro veracruz_image_nitro
```

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

Now, inside the shell running on the container, execute the following:
```bash
cd /work/veracruz
make nitro-sinaloa-test
```
You should see 22 tests pass.