for pid in $(ps -ef | grep -w vts | awk '{print $2}'); do kill $pid; done
for pid in $(ps -ef | grep -w provisioning | awk '{print $2}'); do kill $pid; done
for pid in $(ps -ef | grep corim-psa-decod | awk '{print $2}'); do kill $pid; done
for pid in $(ps -ef | grep scheme-psa-iot | awk '{print $2}'); do kill $pid; done
for pid in $(ps -ef | grep scheme-aws-nitr | awk '{print $2}'); do kill $pid; done
for pid in $(ps -ef | grep corim-nitro-dec | awk '{print $2}'); do kill $pid; done
