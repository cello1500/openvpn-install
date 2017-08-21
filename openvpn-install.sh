#!/bin/bash

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS and Arch Linux
# https://github.com/Angristan/OpenVPN-install


if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 1
fi

if [[ ! -e /dev/net/tun ]]; then
	echo "TUN is not available"
	exit 2
fi

if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit 3
fi

if [[ -e /etc/debian_version ]]; then
	OS="debian"
	# Getting the version number, to verify that a recent version of OpenVPN is available
	VERSION_ID=$(cat /etc/os-release | grep "VERSION_ID")
	RCLOCAL='/etc/rc.local'
	SYSCTL='/etc/sysctl.conf'
	if [[ "$VERSION_ID" != 'VERSION_ID="7"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="8"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="12.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="14.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="16.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="16.10"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="17.04"' ]]; then
		echo "Your version of Debian/Ubuntu is not supported."
		echo "I can't install a recent version of OpenVPN on your system."
		echo ""
		echo "However, if you're using Debian unstable/testing, or Ubuntu beta,"
		echo "then you can continue, a recent version of OpenVPN is available on these."
		echo "Keep in mind they are not supported, though."
		while [[ $CONTINUE != "y" && $CONTINUE != "n" ]]; do
			read -p "Continue ? [y/n]: " -e CONTINUE
		done
		if [[ "$CONTINUE" = "n" ]]; then
			echo "Ok, bye !"
			exit 4
		fi
	fi
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	RCLOCAL='/etc/rc.d/rc.local'
	SYSCTL='/etc/sysctl.conf'
	# Needed for CentOS 7
	chmod +x /etc/rc.d/rc.local
elif [[ -e /etc/arch-release ]]; then
	OS=arch
	RCLOCAL='/etc/rc.local'
	SYSCTL='/etc/sysctl.d/openvpn.conf'
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu, CentOS or ArchLinux system"
	exit 4
fi

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-template.txt ~/$1.ovpn
	echo "" >> ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "" >> ~/$1.ovpn
	echo "# If a tls-auth key is used on the server
# then every client must also have the key." >> ~/$1.ovpn
	echo "key-direction 1" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/tls-auth.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn

	cp ~/$1.ovpn /home/cello/
	chown cello:users /home/cello/$1.ovpn
}

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (LowEndSpirit/Scaleway)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
	IP=$(wget -qO- ipv4.icanhazip.com)
fi

if [[ -e /etc/openvpn/server/server.conf ]]; then
	while :
	do
	clear
		echo "OpenVPN-install (github.com/Angristan/OpenVPN-install)"
		echo ""
		echo "Looks like OpenVPN is already installed"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a cert for a new user"
		echo "   2) Revoke existing user cert"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1)
			echo ""
			echo "Tell me a name for the client cert"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			easyrsa --keysize=3072 build-client-full $CLIENT nopass
			# Generates the custom client.ovpn
			newclient "$CLIENT"
			echo ""
			echo "Client $CLIENT added, certs available at ~/$CLIENT.ovpn"
			exit
			;;
			2)
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit 5
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			easyrsa --batch revoke $CLIENT
			easyrsa gen-crl
			rm -rf pki/reqs/$CLIENT.req
			rm -rf pki/private/$CLIENT.key
			rm -rf pki/issued/$CLIENT.crt
			rm -rf /etc/openvpn/crl.pem
			cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
			chmod 644 /etc/openvpn/crl.pem
			echo ""
			echo "Certificate for client $CLIENT revoked"
			echo "Exiting..."
			exit
			;;
			3)
			echo ""
			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
#				PORT=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
#				if pgrep firewalld; then
#					# Using both permanent and not permanent rules to avoid a firewalld reload.
#					firewall-cmd --zone=public --remove-port=$PORT/udp
#					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
#					firewall-cmd --permanent --zone=public --remove-port=$PORT/udp
#					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
#				fi
#				if iptables -L -n | grep -qE 'REJECT|DROP'; then
#					sed -i "/iptables -I INPUT -p udp --dport $PORT -j ACCEPT/d" $RCLOCAL
#					sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
#					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
#				fi
#				sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
#				if hash sestatus 2>/dev/null; then
#					if sestatus | grep "Current mode" | grep -qs "enforcing"; then
#						if [[ "$PORT" != '1194' ]]; then
#							semanage port -d -t openvpn_port_t -p udp $PORT
#						fi
#					fi
#				fi
				if [[ "$OS" = 'debian' ]]; then
					apt-get remove --purge -y openvpn openvpn-blacklist
				elif [[ "$OS" = 'arch' ]]; then
					pacman -R openvpn --noconfirm
				else
					yum remove openvpn -y
				fi
				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				echo ""
				echo "OpenVPN removed!"
			else
				echo ""
				echo "Removal aborted!"
			fi
			exit
			;;
			4) exit;;
		esac
	done
else
	clear
	echo "Welcome to the secure OpenVPN installer (github.com/Angristan/OpenVPN-install)"
	echo ""
	# OpenVPN setup and first user creation
	echo "I need to ask you a few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "If your server is running behind a NAT, (e.g. LowEndSpirit, Scaleway) leave the IP address as it is. (local/private IP)"
	echo "Otherwise, it should be your public IPv4 address."
	read -p "IP address: " -e -i $IP IP
	echo ""
	echo "What port do you want for OpenVPN?"
	read -p "Port: " -e -i 1194 PORT
	echo ""
	echo "What protocol do you want for OpenVPN?"
	echo "Unless UDP is blocked, you should not use TCP (unnecessarily slower)"
	while [[ $PROTOCOL != "UDP" && $PROTOCOL != "TCP" ]]; do
		read -p "Protocol [UDP/TCP]: " -e -i UDP PROTOCOL
	done
	echo ""
	echo "What DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers (/etc/resolv.conf)"
	echo "   2) FDN (France)"
	echo "   3) DNS.WATCH (Germany)"
	echo "   4) OpenDNS (Anycast: worldwide)"
	echo "   5) Google (Anycast: worldwide)"
	while [[ $DNS != "1" && $DNS != "2" && $DNS != "3" && $DNS != "4" && $DNS != "5" ]]; do
		read -p "DNS [1-5]: " -e -i 1 DNS
	done
	echo ""
	echo "Finally, tell me a name for the client certificate and configuration"
	while [[ $CLIENT = "" ]]; do
		echo "Please, use one word only, no special characters"
		read -p "Client name: " -e -i client CLIENT
	done
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."

	if [[ "$OS" = 'debian' ]]; then
		apt-get install ca-certificates -y
		# We add the OpenVPN repo to get the latest version.
		# Debian 7
		if [[ "$VERSION_ID" = 'VERSION_ID="7"' ]]; then
			echo "deb http://swupdate.openvpn.net/apt wheezy main" > /etc/apt/sources.list.d/swupdate-openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Debian 8
		if [[ "$VERSION_ID" = 'VERSION_ID="8"' ]]; then
			echo "deb http://swupdate.openvpn.net/apt jessie main" > /etc/apt/sources.list.d/swupdate-openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt update
		fi
		# Ubuntu 12.04
		if [[ "$VERSION_ID" = 'VERSION_ID="12.04"' ]]; then
			echo "deb http://swupdate.openvpn.net/apt precise main" > /etc/apt/sources.list.d/swupdate-openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Ubuntu 14.04
		if [[ "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then
			echo "deb http://swupdate.openvpn.net/apt trusty main" > /etc/apt/sources.list.d/swupdate-openvpn.list
			wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
			apt-get update
		fi
		# Ubuntu >= 16.04 and Debian > 8 have OpenVPN > 2.3.3 without the need of a third party repository.
		# The we install OpenVPN
		apt-get install openvpn iptables openssl wget ca-certificates curl -y
	elif [[ "$OS" = 'centos' ]]; then
		yum install epel-release -y
		yum install openvpn iptables openssl wget ca-certificates curl -y
	else
		# Else, the distro is ArchLinux
		echo ""
		echo ""
		echo "As you're using ArchLinux, I need to update the packages on your system to install those I need."
		echo "Not doing that could cause problems between dependencies, or missing files in repositories."
		echo ""
		echo "Continuing will update your installed packages and install needed ones."
		while [[ $CONTINUE != "y" && $CONTINUE != "n" ]]; do
			read -p "Continue ? [y/n]: " -e -i y CONTINUE
		done
		if [[ "$CONTINUE" = "n" ]]; then
			echo "Ok, bye !"
			exit 4
		fi

		if [[ "$OS" = 'arch' ]]; then
		# Install rc.local
#		echo "[Unit]
#Description=/etc/rc.local compatibility
#
#[Service]
#Type=oneshot
#ExecStart=/etc/rc.local
#RemainAfterExit=yes
#
#[Install]
#WantedBy=multi-user.target" > /etc/systemd/system/rc-local.service
#			chmod +x /etc/rc.local
#			systemctl enable rc-local.service
#			if ! grep '#!' $RCLOCAL; then
#				echo "#!/bin/bash" > $RCLOCAL
#			fi

			# Install dependencies
			pacman -Syu openvpn openssl easy-rsa wget ca-certificates curl --needed --noconfirm
		fi

#		if [[ "$OS" = 'arch' ]]; then
#			touch /etc/iptables/iptables.rules # iptables won't start if this file does not exist
#			systemctl enable iptables
#			systemctl start iptables
#		fi
	fi
	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
	        NOGROUP=nogroup
	else
        	NOGROUP=nobody
	fi

	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Get easy-rsa
#	wget -O ~/EasyRSA-3.0.1.tgz https://github.com/OpenVPN/easy-rsa/releases/download/3.0.1/EasyRSA-3.0.1.tgz
#	tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
#	mv ~/EasyRSA-3.0.1/ /etc/openvpn/
#	mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
	ln -s /etc/easy-rsa /etc/openvpn/easy-rsa
	chown -R root:root /etc/openvpn/easy-rsa/
#	rm -rf ~/EasyRSA-3.0.1.tgz
	cd /etc/openvpn/easy-rsa/
#	echo "set_var EASYRSA_KEY_SIZE 3072" > vars
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	easyrsa init-pki
	easyrsa --keysize=3072 --batch build-ca nopass
	openssl dhparam -out dh.pem 3072
	easyrsa --keysize=3072 build-server-full server nopass
	easyrsa --keysize=3072 build-client-full $CLIENT nopass
	easyrsa gen-crl
	# generate tls-auth key
	openvpn --genkey --secret /etc/openvpn/tls-auth.key
	# Move all the generated files
	#cp pki/ca.crt pki/private/ca.key dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	#cp pki/ca.crt pki/private/ca.key dh.pem /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	ln -s /etc/easy-rsa/pki/ca.crt /etc/easy-rsa/pki/private/ca.key /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	#cp pki/issued/server.crt pki/private/server.key dh.pem /etc/openvpn/server
	ln -s /etc/easy-rsa/pki/issued/server.crt /etc/easy-rsa/pki/private/server.key /etc/easy-rsa/dh.pem /etc/openvpn/server
	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo " #################################################
# Sample OpenVPN 2.0 config file for            #
# multi-client server.                          #
#                                               #
# This file is for the server side              #
# of a many-clients <-> one-server              #
# OpenVPN configuration.                        #
#                                               #
# OpenVPN also supports                         #
# single-machine <-> single-machine             #
# configurations (See the Examples page         #
# on the web site for more info).               #
#                                               #
# This config should work on Windows            #
# or Linux/BSD systems.  Remember on            #
# Windows to quote pathnames and use            #
# double backslashes, e.g.:                     #
# "C:\\Program Files\\OpenVPN\\config\\foo.key" #
#                                               #
# Comments are preceded with '#' or ';'         #
#################################################

# Which local IP address should OpenVPN
# listen on? (optional)
;local a.b.c.d

# Which TCP/UDP port should OpenVPN listen on?
# If you want to run multiple OpenVPN instances
# on the same machine, use a different port
# number for each one.  You will need to
# open up this port on your firewall." > /etc/openvpn/server/server.conf
	echo "port $PORT" >> /etc/openvpn/server/server.conf
	echo "" >> /etc/openvpn/server/server.conf

	echo "# TCP or UDP server?
;proto tcp" >> /etc/openvpn/server/server.conf
	if [[ "$PROTOCOL" = 'UDP' ]]; then
		echo "proto udp" >> /etc/openvpn/server/server.conf
	elif [[ "$PROTOCOL" = 'TCP' ]]; then
		echo "proto tcp" >> /etc/openvpn/server/server.conf
	fi
	echo "" >> /etc/openvpn/server/server.conf
	echo "# \"dev tun\" will create a routed IP tunnel,
# \"dev tap\" will create an ethernet tunnel.
# Use \"dev tap0\" if you are ethernet bridging
# and have precreated a tap0 virtual interface
# and bridged it with your ethernet interface.
# If you want to control access policies
# over the VPN, you must create firewall
# rules for the the TUN/TAP interface.
# On non-Windows systems, you can give
# an explicit unit number, such as tun0.
# On Windows, use \"dev-node\" for this.
# On most systems, the VPN will not function
# unless you partially or fully disable
# the firewall for the TUN/TAP interface.
;dev tap
dev tun

# Windows needs the TAP-Win32 adapter name
# from the Network Connections panel if you
# have more than one.  On XP SP2 or higher,
# you may need to selectively disable the
# Windows firewall for the TAP adapter.
# Non-Windows systems usually don't need this.
;dev-node MyTap

# SSL/TLS root certificate (ca), certificate
# (cert), and private key (key).  Each client
# and the server must have their own cert and
# key file.  The server and all clients will
# use the same ca file.
#
# See the \"easy-rsa\" directory for a series
# of scripts for generating RSA certificates
# and private keys.  Remember to use
# a unique Common Name for the server
# and each of the client certificates.
#
# Any X509 key management system can be used.
# OpenVPN can also use a PKCS #12 formatted key file
# (see \"pkcs12\" directive in man page).
ca ../ca.crt
cert server.crt
key server.key  # This file should be kept secret

# Diffie hellman parameters.
# Generate your own with:
#   openssl dhparam -out dh.pem 2048
dh dh.pem

# Network topology
# Should be subnet (addressing via IP)
# unless Windows clients v2.0.9 and lower have to
# be supported (then net30, i.e. a /30 per client)
# Defaults to net30 (not recommended)
topology subnet

# Configure server mode and supply a VPN subnet
# for OpenVPN to draw client addresses from.
# The server will take 10.8.0.1 for itself,
# the rest will be made available to clients.
# Each client will be able to reach the server
# on 10.8.0.1. Comment this line out if you are
# ethernet bridging. See the man page for more info.
server 10.8.0.0 255.255.255.0

# Maintain a record of client <-> virtual IP address
# associations in this file.  If OpenVPN goes down or
# is restarted, reconnecting clients can be assigned
# the same virtual IP address from the pool that was
# previously assigned.
ifconfig-pool-persist ipp.txt

# Configure server mode for ethernet bridging.
# You must first use your OS's bridging capability
# to bridge the TAP interface with the ethernet
# NIC interface.  Then you must manually set the
# IP/netmask on the bridge interface, here we
# assume 10.8.0.4/255.255.255.0.  Finally we
# must set aside an IP range in this subnet
# (start=10.8.0.50 end=10.8.0.100) to allocate
# to connecting clients.  Leave this line commented
# out unless you are ethernet bridging.
;server-bridge 10.8.0.4 255.255.255.0 10.8.0.50 10.8.0.100

# Configure server mode for ethernet bridging
# using a DHCP-proxy, where clients talk
# to the OpenVPN server-side DHCP server
# to receive their IP address allocation
# and DNS server addresses.  You must first use
# your OS's bridging capability to bridge the TAP
# interface with the ethernet NIC interface.
# Note: this mode only works on clients (such as
# Windows), where the client-side TAP adapter is
# bound to a DHCP client.
;server-bridge

# Push routes to the client to allow it
# to reach other private subnets behind
# the server.  Remember that these
# private subnets will also need
# to know to route the OpenVPN client
# address pool (10.8.0.0/255.255.255.0)
# back to the OpenVPN server.
;push \"route 192.168.10.0 255.255.255.0\"
;push \"route 192.168.20.0 255.255.255.0\"

# To assign specific IP addresses to specific
# clients or if a connecting client has a private
# subnet behind it that should also have VPN access,
# use the subdirectory \"ccd\" for client-specific
# configuration files (see man page for more info).

# EXAMPLE: Suppose the client
# having the certificate common name \"Thelonious\"
# also has a small subnet behind his connecting
# machine, such as 192.168.40.128/255.255.255.248.
# First, uncomment out these lines:
;client-config-dir ccd
;route 192.168.40.128 255.255.255.248
# Then create a file ccd/Thelonious with this line:
#   iroute 192.168.40.128 255.255.255.248
# This will allow Thelonious' private subnet to
# access the VPN.  This example will only work
# if you are routing, not bridging, i.e. you are
# using \"dev tun\" and \"server\" directives.

# EXAMPLE: Suppose you want to give
# Thelonious a fixed VPN IP address of 10.9.0.1.
# First uncomment out these lines:
;client-config-dir ccd
;route 10.9.0.0 255.255.255.252
# Then add this line to ccd/Thelonious:
#   ifconfig-push 10.9.0.1 10.9.0.2

# Suppose that you want to enable different
# firewall access policies for different groups
# of clients.  There are two methods:
# (1) Run multiple OpenVPN daemons, one for each
#     group, and firewall the TUN/TAP interface
#     for each group/daemon appropriately.
# (2) (Advanced) Create a script to dynamically
#     modify the firewall in response to access
#     from different clients.  See man
#     page for more info on learn-address script.
;learn-address ./script

# If enabled, this directive will configure
# all clients to redirect their default
# network gateway through the VPN, causing
# all IP traffic such as web browsing and
# and DNS lookups to go through the VPN
# (The OpenVPN server machine may need to NAT
# or bridge the TUN/TAP interface to the internet
# in order for this to work properly).
push \"redirect-gateway def1 bypass-dhcp\"

# Certain Windows-specific network settings
# can be pushed to clients, such as DNS
# or WINS server addresses.  CAVEAT:
# http://openvpn.net/faq.html#dhcpcaveats
# The addresses below refer to the public
# DNS servers provided by opendns.com.
;push \"dhcp-option DNS 208.67.222.222\"
;push \"dhcp-option DNS 208.67.220.220\"" >> /etc/openvpn/server/server.conf

	case $DNS in
		1)
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
			echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
		done
		;;
		2) #FDN
		echo 'push "dhcp-option DNS 80.67.169.12"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 80.67.169.40"' >> /etc/openvpn/server/server.conf
		;;
		3) #DNS.WATCH
		echo 'push "dhcp-option DNS 84.200.69.80"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >> /etc/openvpn/server/server.conf
		;;
		4) #OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5) #Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
	esac

	echo "" >> /etc/openvpn/server/server.conf
	echo "# Uncomment this directive to allow different
# clients to be able to \"see\" each other.
# By default, clients will only see the server.
# To force clients to only see the server, you
# will also need to appropriately firewall the
# server's TUN/TAP interface.
;client-to-client

# Uncomment this directive if multiple clients
# might connect with the same certificate/key
# files or common names.  This is recommended
# only for testing purposes.  For production use,
# each client should have its own certificate/key
# pair.
#
# IF YOU HAVE NOT GENERATED INDIVIDUAL
# CERTIFICATE/KEY PAIRS FOR EACH CLIENT,
# EACH HAVING ITS OWN UNIQUE \"COMMON NAME\",
# UNCOMMENT THIS LINE OUT.
;duplicate-cn

# The keepalive directive causes ping-like
# messages to be sent back and forth over
# the link so that each side knows when
# the other side has gone down.
# Ping every 10 seconds, assume that remote
# peer is down if no ping received during
# a 120 second time period.
keepalive 10 120

# For extra security beyond that provided
# by SSL/TLS, create an \"HMAC firewall\"
# to help block DoS attacks and UDP port flooding.
#
# Generate with:
#   openvpn --genkey --secret ta.key
#
# The server and each client must have
# a copy of this key.
# The second parameter should be '0'
# on the server and '1' on the clients.
tls-auth ../tls-auth.key 0 # This file is secret

# Select a cryptographic cipher.
# This config item must be copied to
# the client config file as well.
# Note that v2.4 client/server will automatically
# negotiate AES-256-GCM in TLS mode.
# See also the ncp-cipher option in the manpage
cipher AES-256-CBC

# Enable compression on the VPN link and push the
# option to the client (v2.4+ only, for earlier
# versions see below)
;compress lz4-v2
;push \"compress lz4-v2\"

# For compression compatible with older clients use comp-lzo
# If you enable it here, you must also
# enable it in the client config file.
comp-lzo

# The maximum number of concurrently connected
# clients we want to allow.
;max-clients 100

# It's a good idea to reduce the OpenVPN
# daemon's privileges after initialization.
#
# You can uncomment this out on
# non-Windows systems.
user nobody
group $NOGROUP

# The persist options will try to avoid
# accessing certain resources on restart
# that may no longer be accessible because
# of the privilege downgrade.
persist-key
persist-tun

# Output a short status file showing
# current connections, truncated
# and rewritten every minute (default) or every 5 seconds.
status openvpn-status.log 5

# By default, log messages will go to the syslog (or
# on Windows, if running as a service, they will go to
# the \"\Program Files\OpenVPN\log\" directory).
# Use log or log-append to override this default.
# \"log\" will truncate the log file on OpenVPN startup,
# while \"log-append\" will append to it.  Use one
# or the other (but not both).
;log         openvpn.log
;log-append  openvpn.log

# Set the appropriate level of log
# file verbosity.
#
# 0 is silent, except for fatal errors
# 4 is reasonable for general usage
# 5 and 6 can help to debug connection problems
# 9 is extremely verbose
verb 3

# Silence repeating messages.  At most 20
# sequential messages of the same message
# category will be output to the log.
;mute 20

# Notify the client that when the server restarts so it
# can automatically reconnect.
explicit-exit-notify 1

tls-server
tls-version-min 1.2
;tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
crl-verify ../crl.pem
auth SHA512

push \"dhcp-option DOMAIN home\"
sndbuf 0
rcvbuf 0" >> /etc/openvpn/server/server.conf

	# Create the sysctl configuration file if needed (mainly for Arch Linux)
	if [[ ! -e $SYSCTL ]]; then
		touch $SYSCTL
	fi

	# Enable net.ipv4.ip_forward for the system
	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' $SYSCTL
	if ! grep -q "\<net.ipv4.ip_forward\>" $SYSCTL; then
		echo 'net.ipv4.ip_forward=1' >> $SYSCTL
	fi
	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Set NAT for the VPN subnet
#	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
#	sed -i "0 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
#	if pgrep firewalld; then
#		# We don't use --add-service=openvpn because that would only work with
#		# the default port. Using both permanent and not permanent rules to
#		# avoid a firewalld reload.
#		if [[ "$PROTOCOL" = 'UDP' ]]; then
#			firewall-cmd --zone=public --add-port=$PORT/udp
#			firewall-cmd --permanent --zone=public --add-port=$PORT/udp
#		elif [[ "$PROTOCOL" = 'TCP' ]]; then
#			firewall-cmd --zone=public --add-port=$PORT/tcp
#			firewall-cmd --permanent --zone=public --add-port=$PORT/tcp
#		fi
#		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
#		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
#	fi
#	if iptables -L -n | grep -qE 'REJECT|DROP'; then
#		# If iptables has at least one REJECT rule, we asume this is needed.
#		# Not the best approach but I can't think of other and this shouldn't
#		# cause problems.
#		if [[ "$PROTOCOL" = 'UDP' ]]; then
#			iptables -I INPUT -p udp --dport $PORT -j ACCEPT
#		elif [[ "$PROTOCOL" = 'TCP' ]]; then
#			iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
#		fi
#		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
#		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
#		if [[ "$PROTOCOL" = 'UDP' ]]; then
#			sed -i "1 a\iptables -I INPUT -p udp --dport $PORT -j ACCEPT" $RCLOCAL
#		elif [[ "$PROTOCOL" = 'TCP' ]]; then
#			sed -i "1 a\iptables -I INPUT -p tcp --dport $PORT -j ACCEPT" $RCLOCAL
#		fi
#		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
#		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
#	fi
#	# If SELinux is enabled and a custom port was selected, we need this
#	if hash sestatus 2>/dev/null; then
#		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
#			if [[ "$PORT" != '1194' ]]; then
#				# semanage isn't available in CentOS 6 by default
#				if ! hash semanage 2>/dev/null; then
#					yum install policycoreutils-python -y
#				fi
#				if [[ "$PROTOCOL" = 'UDP' ]]; then
#					semanage port -a -t openvpn_port_t -p udp $PORT
#				elif [[ "$PROTOCOL" = 'TCP' ]]; then
#					semanage port -a -t openvpn_port_t -p tcp $PORT
#				fi
#			fi
#		fi
#	fi
	# And finally, restart OpenVPN
	if [[ "$OS" = 'debian' ]]; then
		# Little hack to check for systemd
		if pgrep systemd-journal; then
			systemctl restart openvpn@server.service
		else
			/etc/init.d/openvpn restart
		fi
	else
		if [[ "$OS" = 'arch' ]]; then
			systemctl start openvpn-server@server.service
			systemctl enable openvpn-server@server.service
		elif pgrep systemd-journal; then
			systemctl restart openvpn@server.service
			systemctl enable openvpn@server.service
		else
			service openvpn restart
			chkconfig openvpn on
		fi
	fi
	# Try to detect a NATed connection and ask about it to potential LowEndSpirit/Scaleway users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
                echo "If your server is NATed (e.g. LowEndSpirit, Scaleway, or behind a router),"
                echo "then I need to know the address that can be used to access it from outside."
                echo "If that's not the case, just ignore this and leave the next field blank"
                read -p "External IP or domain name: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# client-template.txt is created so we have a template to add further users later
	echo " ##############################################
# Sample client-side OpenVPN 2.0 config file #
# for connecting to multi-client server.     #
#                                            #
# This configuration can be used by multiple #
# clients, however each client should have   #
# its own cert and key files.                #
#                                            #
# On Windows, you might want to rename this  #
# file so it has a .ovpn extension           #
##############################################

# Specify that we are a client and that we
# will be pulling certain config file directives
# from the server.
client

# Use the same setting as you are using on
# the server.
# On most systems, the VPN will not function
# unless you partially or fully disable
# the firewall for the TUN/TAP interface.
;dev tap
dev tun

# Windows needs the TAP-Win32 adapter name
# from the Network Connections panel
# if you have more than one.  On XP SP2,
# you may need to disable the firewall
# for the TAP adapter.
;dev-node MyTap

# Are we connecting to a TCP or
# UDP server?  Use the same setting as
# on the server.
;proto tcp " > /etc/openvpn/client-template.txt

	if [[ "$PROTOCOL" = 'UDP' ]]; then
		echo "proto udp" >> /etc/openvpn/client-template.txt
	elif [[ "$PROTOCOL" = 'TCP' ]]; then
		echo "proto tcp-client" >> /etc/openvpn/client-template.txt
	fi

	echo "" >> /etc/openvpn/client-template.txt
	echo "# The hostname/IP and port of the server.
# You can have multiple remote entries
# to load balance between the servers.
;remote my-server-1 1194
;remote my-server-2 1194" >> /etc/openvpn/client-template.txt


	echo "remote $IP $PORT" >> /etc/openvpn/client-template.txt
	echo "" >> /etc/openvpn/client-template.txt
	echo "# Choose a random host from the remote
# list for load-balancing.  Otherwise
# try hosts in the order specified.
;remote-random

# Keep trying indefinitely to resolve the
# host name of the OpenVPN server.  Very useful
# on machines which are not permanently connected
# to the internet such as laptops.
resolv-retry infinite

# Most clients don't need to bind to
# a specific local port number.
nobind

# Downgrade privileges after initialization (non-Windows only)
user nobody
group nobody

# Try to preserve some state across restarts.
persist-key
persist-tun

# If you are connecting through an
# HTTP proxy to reach the actual OpenVPN
# server, put the proxy server/IP and
# port number here.  See the man page
# if your proxy server requires
# authentication.
;http-proxy-retry # retry on connection failures
;http-proxy [proxy server] [proxy port #]

# Wireless networks often produce a lot
# of duplicate packets.  Set this flag
# to silence duplicate packet warnings.
;mute-replay-warnings

# Verify server certificate by checking that the
# certicate has the correct key usage set.
# This is an important precaution to protect against
# a potential attack discussed here:
#  http://openvpn.net/howto.html#mitm
#
# To use this feature, you will need to generate
# your server certificates with the keyUsage set to
#   digitalSignature, keyEncipherment
# and the extendedKeyUsage to
#   serverAuth
# EasyRSA can do this for you.
remote-cert-tls server

# Select a cryptographic cipher.
# If the cipher option is used on the server
# then you must also specify it here.
# Note that v2.4 client/server will automatically
# negotiate AES-256-GCM in TLS mode.
# See also the ncp-cipher option in the manpage
cipher AES-256-CBC

# Enable compression on the VPN link.
# Don't enable this unless it is also
# enabled in the server config file.
comp-lzo

# Set log file verbosity.
verb 3

# Silence repeating messages
;mute 20" >> /etc/openvpn/client-template.txt

	echo "" >> /etc/openvpn/client-template.txt
	echo "auth SHA512
tls-client
tls-version-min 1.2
;tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
setenv opt block-outside-dns
verb 3
sndbuf 0
rcvbuf 0" >> /etc/openvpn/client-template.txt

	# Generate the custom client.ovpn
	newclient "$CLIENT"
	echo ""
	echo "Finished!"
	echo ""
	echo "Your client config is available at ~/$CLIENT.ovpn"
	echo "If you want to add more clients, you simply need to run this script another time!"
fi
exit 0;
