#!/bin/bash

# Script to perform local security checks

function checks() {

	if [[ $2 != $3 ]]
	then
		echo -e "\e[1;31mThe $1 policy is not compliant. The current should be: $2, the current value is: $3\e[0m"
	
	else
		echo -e "\e[1;32mThe $1 policy is compliant. Current Value: $3\e[0m"
	fi

}

# Check the password max days policy
pmax=$(egrep -i '^PASS_MAX_DAYS' /etc/login.defs | awk ' { print $2 } ')
checks "Password Max Days" "365" "${pmax}"
# Provide remediation if needed
if [[ ${pmax} != "365" ]]
then 
	echo "Remediation:"
	echo "Edit /etc/login.defs and set:"
	echo -e "PASS_MAX_DAYS = ${pmax}\nto\nPASS_MAX_DAYS = 365"
fi

# Check the pass min days between changes
pmin=$(egrep -i '^PASS_MIN_DAYS' /etc/login.defs | awk ' { print $2 } ')
checks "Password Min Days" "14" "${pmin}"
# Provide remediation if needed
if [[ ${pmin} != "14" ]]
then 
    echo "Remediation:"
    echo "Edit /etc/login.defs and set:"
    echo -e "PASS_MIN_DAYS = ${pmin}\nto\nPASS_MAX_DAYS = 14"
fi

# Check the pass warn age
pwarn=$(egrep -i '^PASS_WARN_AGE' /etc/login.defs | awk ' { print $2 } ')
checks "Password Warn Age" "7" "${pwarn}"
# Provide remediation if needed
if [[ ${pwarn} != "7" ]]
then 
    echo "Remediation:"
    echo "Edit /etc/login.defs and set:"
    echo -e "PASS_WARN_AGE = ${pwarn}\nto\nPASS_MAX_DAYS = 7"
fi

# Check the SSH UsePam Configuration
chkSSHPAM=$(egrep -i "^UsePAM" /etc/ssh/sshd_config | awk ' { print $2 } ')
checks "SSH UsePam" "yes" "${chkSSHPAM}"
# Provide remediation if needed
if [[ ${chkSSHPAM} != "yes" ]]
then 
    echo "Remediation:"
    echo "Edit /etc/ssh/sshd_config and set:"
    echo -e "SSH UsePam ${chkSSHPAM}\nto\nPASS_MAX_DAYS yes"
fi

# Check permission on users home directory
for eachDir in $(ls -l /home | egrep "^d" | awk ' { print $3 } ')
do 
	chDir=$(ls -ld /home/${eachDir} | awk ' { print $1 } ' )
	# Check Each home directory
	checks "Home Directory ${eachDir}" "drwx------" "${chDir}"
	# Provide remediation if needed
	if [[ ${chDir} != "drwx------" ]]
	then 
    	echo "Remediation:"
    	echo -e "Execute:\nsudo chmod 700 /home/${eachDir}"
	fi
done

# Check IP Forwarding Configuration
ipForwardChk=$(egrep -i "^#net.ipv4.ip_forward" /etc/sysctl.conf | cut -d "=" -f2)
checks "IP Forwarding" "0" "${ipForwardChk}"
# Provide remediation if needed
if [[ ${ipForwardChk} != "0" ]]
then 
    echo "Remediation:"
    echo "Edit /etc/sysctl.conf and set:"
    echo -e "net.ipv4.ip_forward=${ipForwardChk}\nto\nnet.ipv4.ip_forward=0"
	echo -e "Then run:\nsysctl -w"
fi

# Check ICMP Redirects Configuration
allAcptRedirects=$(egrep -i "^#net.ipv4.conf.all.accept_redirects" /etc/sysctl.conf | awk ' { print $3 } ')
checks "Accept All Redirects" "0" "${allAcptRedirects}"
#Provide remediation if needed
if [[ ${allAcptRedirects} != "0" ]]
then
	echo "Remediation:"
	echo "Edit /etc/sysctl.conf and set:"
	echo -e "net.ipv4.conf.all.accept_redirects = ${allAcptRedirects}\nto\net.ipv4.conf.all.accpet_redirects = 0"
	echo -e "Then run:\nsysctl -w"
fi

# Ensure permissions on /etc/crontab are configured
crontab=$(stat /etc/crontab | egrep -i "^Access: \(")
checks "/etc/crontab Configuration" "Access: (0644/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)" "${crontab}" 
#Provide remediation if needed
if [[ ${crontab} != "Access: (0644/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/crontab\nchmod og-rwx /etc/crontab"
fi

#Ensure permissions on /etc/cron.hourly are configured
cronhour=$(stat /etc/cron.hourly | egrep -i "^Access: \(")
checks "/etc/cron.hourly Configuration" "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" "${cronhour}"
#Provide remediation if needed
if [[ ${cronhour} != "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/cron.hourly\nchmod og-rwx /etc/cron.hourly"
fi

#Ensure permissions on /etc/cron.daily are configured
crondaily=$(stat /etc/cron.daily | egrep -i "^Access: \(")
checks "/etc/cron.daily Configuration" "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" "${crondaily}"
#Provide remediation if needed
if [[ ${crondaily} != "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/cron.daily\nchmod og-rwx /etc/cron.daily"
fi

#Ensure permissions on /etc/cron.weekly are configured
cronweekly=$(stat /etc/cron.weekly | egrep -i "^Access: \(")
checks "/etc/cron.weekly Configuration" "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" "${cronweekly}"
#Provide remediation if needed
if [[ ${cronweekly} != "Access: (0700/drwx------) Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/cron.weekly\nchmod og-rwx /etc/cron.weekly"
fi

#Ensure permissions on /etc/cron.monthly are configured
cronmonthly=$(stat /etc/cron.monthly | egrep -i "^Access: \(")
checks "/etc/cron.monthly Configuration" "Access: (0700/drwx------)  Uid: (    0/    root)   Gid: (    0/    root)" "${cronmonthly}"
#Provide remediation if needed
if [[ ${cronmonthly} != "Access: (0700/drwx------) Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/cron.monthly\nchmod og-rwx /etc/cron.monthly"
fi

#Ensure permissions on /etc/passwd are configured
passwd=$(stat /etc/passwd | egrep -i "^Access: \(")
checks "/etc/passwd Configuration" "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" "${passwd}"
#Provide remediation if needed
if [[ ${passwd} != "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/passwd\nchmod 644 /etc/passwd"
fi

#Ensure permissions on /etc/shadow are configured
shadow=$(stat /etc/shadow | egrep -i "^Access: \(")
checks "/etc/shadow Configuration" "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)" "${shadow}"
#Provide remediation if needed
if [[ ${shadow} != "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:shadow /etc/shadow\nchmod o-rwx,g-wx /etc/shadow"
fi

#Ensure permissions on /etc/group are configured
group=$(stat /etc/group | egrep -i "^Access: \(")
checks "/etc/group Configuration" "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" "${group}"
#Provide remediation if needed
if [[ ${group} != "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/group\nchmod 644 /etc/group"
fi

#Ensure permissions on /etc/gshadow are configured
gshadow=$(stat /etc/gshadow | egrep -i "^Access: \(")
checks "/etc/gshadow Configuration" "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)" "${gshadow}"
#Provide remediation if needed
if [[ ${gshadow} != "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:shadow /etc/gshadow\nchmod o-rwx,g-rw /etc/gshadow"
fi

#Ensure permissions on /etc/passwd- are configured
passwd2=$(stat /etc/passwd- | egrep -i "^Access: \(")
checks "/etc/passwd- Configuration" "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" "${passwd2}"
#Provide remediation if needed
if [[ ${passwd2} != "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/passwd-\nchmod u-x,go-wx /etc/passwd-"
fi

#Ensure permissions on /etc/shadow- are configured
shadow2=$(stat /etc/shadow- | egrep -i "^Access: \(")
checks "/etc/shadow- Configuration" "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)" "${shadow2}"
#Provide remediation if needed
if [[ ${shadow2} != "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:shadow /etc/shadow-\nchmod o-rwx,g-rw /etc/shadow-"
fi

#Ensure permissions on /etc/group- are configured
group2=$(stat /etc/group- | egrep -i "^Access: \(")
checks "/etc/group- Configuration" "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" "${group2}"
#Provide remediation if needed
if [[ ${group2} != "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:root /etc/group-\nchmod u-x,go-wx /etc/group-"
fi

#Ensure permissions on /etc/gshadow- are configured
gshadow2=$(stat /etc/gshadow- | egrep -i "^Access: \(")
checks "/etc/gshadow- Configuration" "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)" "${gshadow2}"
#Provide remediation if needed
if [[ ${gshadow2} != "Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)" ]]
then
    echo "Remediation:"
    echo -e "Run:\nchown root:shadow /etc/gshadow-\nchmod o-rwx,g-rw /etc/gshadow-"
fi

#Ensure no legacy "+" entries exist in /etc/passwd
legacyPass=$(grep '^\+:' /etc/passwd)
checks "Passwd Legacy Entries" "" "${legacyPass}"
#Provide remediation if needed
if [[ ${legacyPass} != "" ]]
then
    echo "Remediation:"
    echo "Remove any legacy '+' entries from /etc/passwd"
fi

#Ensure no legacy "+" entries exist in /etc/shadow
legacyShadow=$(sudo grep '^\+:' /etc/shadow)
checks "Shadow Legacy Entries" "" "${legacyShadow}"
#Provide remediation if needed
if [[ ${legacyShadow} != "" ]]
then
    echo "Remediation:"
    echo "Remove any legacy '+' entries from /etc/shadow"
fi

#Ensure no legacy "+" entries exist in /etc/group
legacyGroup=$(grep '^\+:' /etc/group)
checks "Group Legacy Entries" "" "${legacyGroup}"
#Provide remediation if needed
if [[ ${legacyGroup} != "" ]]
then
    echo "Remediation:"
    echo "Remove any legacy '+' entries from /etc/group"
fi

#Ensure root is the only UID 0 account
UID0=$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }')
checks "UID 0 Accounts" "root" "${UID0}"
#Provide remediation if needed
if [[ ${UID0} != "root" ]]
then
    echo "Remediation:"
    echo "Remove any users other than root with UID 0 or assign them a new UID if appropriate"
fi
