#!/bin/bash

# Storyline: Extract IPs from emergingthreats.net and create a firewall ruleset

# Check to see if badIPs.txt already exists
if [[ -f "badIPs.txt" ]]
then 
        # Check to see if it should be overwritten
        echo "The file already exists."
        echo -n "Do you want to overwrite it? [y|N]"
        read to_overwrite

	# if no, exit
        if [[ "${to_overwrite}" == "N" || "${to_overwrite}" == "" || "${to_overwrite}" == "n" ]]
        then
                echo "Exiting..."
		sleep 1
                exit 0
	# if yes, continue
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

# Ruleset creation 

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

