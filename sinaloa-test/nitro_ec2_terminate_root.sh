INFO=$(aws ec2 describe-instances --filters "Name=tag:Veracruz,Values=RootEnclave"| jq -r '.Reservations[].Instances[].InstanceId')
echo $INFO

RESULT=$(aws ec2 terminate-instances --instance-ids $INFO)
echo $RESULT
