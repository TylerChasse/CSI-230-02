#!/bin/bash

# Storyline: Menu for admin, VPN, and Security functions

# Function for when invalid input is entered
function invalid_opt() {
	echo ""
        echo "Invalid option"
        echo ""
        sleep 2

}

# Main menu function
function menu() {

	# Clears the screen
	clear
	# Provide Options
	echo "[1] Admin Menu"
	echo "[2] Security Menu"
	echo "[3] Exit"
	read -p "Please enter a choice above: " choice
	# Act on choice
	case "$choice" in

		1) admin_menu
		;;
		2) security_menu
		;;
		3) exit 0
		;;
		*) 
			invalid_opt
			# Call the main menu
			menu
		;;

	esac

}

# Admin menu function
function admin_menu() {
	# Clear the screen
	clear
	# Provide options
	echo "[L] List Running Processes"
        echo "[N] Network Sockets"
	echo "[V] VPN Menu"
        echo "[4] Exit"
        read -p "Please enter a choice above: " choice
	# Act on choice
	case "$choice" in
		L|l) ps -ef |less
		;;
		N|n) netstat -an --inet |less
		;;
		V|v) vpn_menu
		;;
		4) exit 0
		;;
		*) invalid_opt
		;;
	esac
# Return to admin menu
admin_menu
}

# VPN menu function
function vpn_menu() {
	# Clear the screen
	clear
	# Provide options
	echo "[A] Add a peer"
	echo "[D] Delete a peer"
	echo "[B] Back to admin menu"
	echo "[M] Main Menu"
	echo "[E] Exit"
	read -p "Please select an option: " choice
	# Act on choice
	case "$choice" in
		A|a) 
			bash peer.bash
			tail -6 wg0.conf |less
		;;
		D|d)
			# Create a prompt for the user to delete
			read -p "Enter user to delete: " user
			# Call manage-user.bash and pass the proper switches and argument
			# to delete the user
			bash manage-users.bash -d -u "${user}"
		;;
		B|b) admin_menu
		;;
		M|m) menu
		;;
		E|e) exit 0
		;;
		*) invalid_opt
		;;
	esac
# Return to vpn menu
vpn_menu
}

# Security menu function
function security_menu() {
	# Clear the screen
	clear
	# Provide options
	echo "[N] Network Sockets"
	echo "[U] Users With UID 0"
	echo "[L] Last 10 Logged in Users"
	echo "[C] Currently Logged in Users"
	echo "[B] Block List Menu"
	echo "[E] Exit"
	read -p "Please select an option: " choice
	# Act on choice
	case "$choice" in
		N|n) netstat -an --inet |less
		;;
		# Used https://unixstackexchange.com/questions/36580/how-can-look-up-a-username-by-id-in-linux
		# to help with finding by id
		U|u) id -nu 0 |less
		;;
		# Used https://devconnected.com/how-to-find-last-login-on-linux/
		# to help with displaying last logins
		L|l) last | grep -v 'reboot' | head -n 10 |less
		;;
		# Used https://www.makeuseof.com/list-logged-in-users-on-linux/
		# to help with displaying logged in users
		C|c) users |less
		;;
		E|e) exit 0
		;;
		B|b) block_list_menu
		;;
		*) invalid_opt
		;;
	esac	
# Return to security menu
security_menu
}

function block_list_menu() {
	# Clear the screen
	clear
	# Provide options
	echo "[I] IPtables blocklist generator"
	echo "[C] Cisco blocklist generator"
	echo "[W] Windows blocklist generator"
	echo "[M] Mac blocklist generator"
	echo "[U] Cisco URL blocklist generator"
	echo "[E] Exit"
	read -p "Please select an option: " choice
	# Act on choice
	case "$choice" in
		I|i) bash parse-threat.bash -i 
		;;
		C|c) bash parse-threat.bash -c 
		;;
		W|w) bash parse-threat.bash -w 
		;;
		M|m) bash parse-threat.bash -m 
		;;
		U|u) bash parse-threat.bash -u 
		;;
		E|e) exit 0
		;;
		*) invalid_opt
		;;
	esac
# Return to block list menu
block_list_menu
}

# Call the menu function
menu
 
