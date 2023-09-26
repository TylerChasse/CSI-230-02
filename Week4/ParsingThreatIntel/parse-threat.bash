#!/bin/bash

# Storyline: Extract IPs from emergingthreats.net and create a firewall ruleset

# alert tcp [2.57.234.0/23,2.58.148.0/22,5.42.199.0/24,5.134.128.0/19,5.183.60.0/22,5.188.10.0/23,24.137.16.0/20,24.170.208.0/20
#,24.233.0.0/19,24.236.0.0/19,27.123.208.0/22,27.126.160.0/20,27.146.0.0/16,31.24.81.0/24,31.41.244.0/24,31.217.252.0/24,31.222.
# 236.0/24,36.0.8.0/21,36.37.48.0/20,36.116.0.0/16]
# any -> $HOME_NET any (msg:"ET DROP Spamhaus DROP Listed Traffic Inbound group 1"; flags:S;
# reference:url,www.spamhaus.org/drop/drop.lasso; threshold: type limit, track by_src, seconds 3600, count 1;
# classtype:misc-attack; flowbits:set,ET.Evil; flowbits:set,ET.DROPIP; sid:2400000; rev:3747; metadata:affected_product Any,
# attack_target Any, deployment Perimeter, tag Dshield, signature_severity Minor, created_at 2010_12_30, updated_at 2023_09_20;)

# Regex to extract the networks
# 2.   57.   234.   0/    23


if [[ -f "badIPs.txt" ]]
then 
        # Check to see if it should be overwritten
        echo "The file already exists."
        echo -n "Do you want to overwrite it? [y|N]"
        read to_overwrite

        if [[ "${to_overwrite}" == "N" || "${to_overwrite}" == "" || "${to_overwrite}" == "n" ]]
        then
                echo "Exiting..."
		sleep 1
                exit 0
        elif [[ "${to_overwrite}" == "y" ]]
        then
                echo "Downloading the file..."
		sleep 1
	# If they don't specify y/N then error
        else
                echo "Invalid value"
		sleep 1
                exit 1
        fi
fi

# Download the file
wget http://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules -O badIPs.txt 

# Act on input
while getopts 'icwmu' OPTION; do
        case "$OPTION" in

        i) iptables={$OPTION} 
	;;
        c) cisco={$OPTION}
        ;;
	w) wfirewall={$OPTION}
	;;
	m) mac={$OPTION} 
	;;
	u) ciscoURL={$OPTION}
	;;
        *) 
         	echo "Invalid value"
		exit 1
        ;;

	esac
done


if [[ ${iptables} ]]
then
	# Get IPs from file
	egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/[0-9]{1,2}' badIPs.txt | tee badIPs2.txt
	for eachIP in $(cat badIPs2.txt)
        do
		# Echo rule for each IP
                echo "iptables -A INPUT -s ${eachIP} -j DROP" | tee -a badIPs.iptables 
        done
	# Remove temporary file
	rm badIPs2.txt
        echo 'Created IP Tables for firewall drop rules in file "badips.iptables"'
	sleep 3
fi

if [[ ${cisco} ]]
then
	# Get IPs from file
	egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/[0-9]{1,2}' badIPs.txt | tee badips.nocidr
	for eachip in $(cat badips.nocidr)
	do
		# Echo rule for each IP
		echo "deny ip host ${eachip} any" | tee -a badips.cisco
	done
	# Remove temporary file
	rm badips.nocidr
	echo 'Created IP Tables for firewall drop rules in file "badips.cisco"'
	sleep 3
fi

if [[ ${wfirewall} ]]
then
	# Get IPs from file
	egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/[0-9]{1,2}' badIPs.txt | tee badips.windowsform
	for eachip in $(cat badips.windowsform)
	do
		# Echo rule for each IP
		echo "netsh advfirewall firewall add rule name=\"BLOCK IP ADDRESS - ${eachip}\" dir=in action=block remoteip=${eachip}" | tee -a badips.netsh
	done
	# Remove temporary file
	rm badips.windowsform
	echo "Created IP Tables for firewall drop rules in file \"badips.netsh\""
	sleep 3
fi

if [[ ${mac} ]]
then
	# Get IPs from file
	egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/[0-9]{1,2}' badIPs.txt | tee badIPs2.txt 
	for eachIP in $(cat badIPs2.txt)
        do
		# Echo rule for each IP
	        echo "block in from ${eachIP} to any" | tee -a pf.conf
        done
	# Remove temporary file
	rm badIPs2.txt
        echo 'Created IP Tables for firewall drop rules in file "pf.conf"'
	sleep 3
fi

if [[ ${ciscoURL} ]]
then
	# Download file
	wget https://raw.githubusercontent.com/botherder/targetedthreats/master/targetedthreats.csv -O /tmp/targetedthreats
        # Get domain URLs from file
	egrep 'domain' /tmp/targetedthreats | awk -F ',' '{print $2}' | tee badURLs.txt 
        echo "class-map match-any BAD_URLS" | tee ciscoURLfilter.txt
        for eachURL in $(cat badURLs.txt)
        do
		# Echo rule for each URL
	        echo "match protocol http host ${eachURL}"
        done
	echo 'Created ruleset for Cisco URL filters'
	sleep 3
fi

