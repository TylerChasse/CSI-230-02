touch output.txt
ip addr > output.txt
awk '/scope global dynamic/ {print $2}' output.txt
