#!/bin/bash

# AUTHORS
#
# The Veracruz Development Team.
#
# COPYRIGHT
#
# See the `LICENSE.markdown` file in the Veracruz root directory for licensing
# and copyright information.

# Terminates any EC2 instances that were started by the Veracruz server for the
# AWS Nitro enclaves feature.

INFO=$(aws ec2 describe-instances --filters "Name=tag:Veracruz,Values=RootEnclave"| jq -r '.Reservations[].Instances[].InstanceId')
echo $INFO

RESULT=$(aws ec2 terminate-instances --instance-ids $INFO)
echo $RESULT
