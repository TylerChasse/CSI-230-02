#!/bin/bash

# Read in file

# Arguments using the position, they start at $1
APACHE_LOG=$1

# Check if file exists
if [[ ! -f ${APACHE_LOG} ]]
then
	echo "Please specifiy the path to a log file"
	exit 1
fi

# Looking for web scanners
sed -e "s/\[//g" -e "s/\"//g" ${APACHE_LOG} | \
egrep -i "test|shell|echo|passwd|select|phpmyadmin|setup|admin|w00t" | \
# Format apache log
awk ' BEGIN { format = "%-15s %-20s %-7s %-6s %-10s %s\n"
				printf format, "IP", "Date", "Method", "Status", "Size", "URI"
				printf format, "--", "----", "------", "------", "----", "---"}
	
{ printf format, $1, $4, $6, $9, $10, $7 } '

# Create IPTables ruleset
# Get IPs from file and remove duplicates
awk ' { print $1 } ' ${APACHE_LOG} | sort -u | tee IPs.txt
for eachIP in $(cat IPs.txt)
do
	# Echo rule for each IP
	echo "iptables -A INPUT -s ${eachIP} -j DROP" | tee -a ruleset.iptables 
done
# Remove temporary file
rm IPs.txt
echo 'Created IP Tables for firewall drop rules in file "ruleset.iptables"'
