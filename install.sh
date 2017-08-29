#!/bin/sh
set -e

#
# This script is meant for quick & easy install via:
#    1. sudo sh -c "$(curl -sSL https://s3-us-west-2.amazonaws.com/www.lacework.net/download/2017-08-17_master_81de8513ee1313eed3b80d415765c8795be5b3f0/install.sh)" 
#    or
#    1. "curl -sSL https://s3-us-west-2.amazonaws.com/www.lacework.net/download/2017-08-17_master_81de8513ee1313eed3b80d415765c8795be5b3f0/install.sh > /tmp/install.sh"
#    2. sudo sh /tmp/install.sh
#    or
#    1. export LaceworkAccessToken="$1"
#    2. /usr/bin/docker run -d --name datacollector --net=host --pid=host --privileged --volume /var/lib/lacework:/var/lib/lacework --volume /var/log:/var/log --volume /var/run:/var/run --volume /etc/passwd:/etc/passwd --volume /etc/group:/etc/group lacework/datacollector:latest
#

SYSTEMD_OVERRIDE=no
STRICT_MODE=no
# Agent version
version=1.0.91
commit_hash=2017-08-17_master_81de8513ee1313eed3b80d415765c8795be5b3f0
deb_sha1=94450fa1cd9fde2e03b49d1c8269f73a4b385dad
rpm_sha1=201275189801bee82e81b696cca176395572e7fc
dc_sha1=f24ff4b894c321f2a6035343e3641417af2dd6a6

pkgname=lacework
download_url="https://s3-us-west-2.amazonaws.com/www.lacework.net/download/${commit_hash}"

ARG1=93fa0e075bf1702f3d67017309c3ada6d3b7cb1746237cae6639a831
usedocker=no

check_bash() {
	if [ "$ARG1" = "" ];
	then
		if [ "$0" = "bash" ] ||  [ "$0" = "sh" ];
		then
			cat <<-EOF
			 ----------------------------------
			    Error:
			    This scripts needs user input and is unable to read the input. 
			    Please run 1 of the following ways
			        
			        1. sudo sh -c "\$(curl -sSL ${download_url}/install.sh)" 
			        
			    OR a 2 step process to download file to /tmp and run it from there.
			        
			        1. "curl -sSL ${download_url}/install.sh > /tmp/install.sh"
		        	2. sudo sh /tmp/install.sh
			 ----------------------------------
			EOF
			exit 100
		fi
	fi
}

command_exists() {
	command -v "$@" > /dev/null 2>&1
}

# Check if this is a forked Linux distro
check_forked() {
	# Check for lsb_release command existence, it usually exists in forked distros
	if command_exists lsb_release; then
		# Check if the `-u` option is supported
		set +e
		lsb_release -a -u > /dev/null 2>&1
		lsb_release_exit_code=$?
		set -e

		# Check if the command has exited successfully, it means we're in a forked distro
		if [ "$lsb_release_exit_code" = "0" ]; then
			# Print info about current distro
			cat <<-EOF
			You're using '$lsb_dist' version '$dist_version'.
			EOF

			# Get the upstream release info
			lsb_dist=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'id' | cut -d ':' -f 2 | tr -d '[[:space:]]')
			dist_version=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'codename' | cut -d ':' -f 2 | tr -d '[[:space:]]')

			# Print info about upstream distro
			cat <<-EOF
			Upstream release is '$lsb_dist' version '$dist_version'.
			EOF
		fi
	fi
}

check_x64() {
	case "$(uname -m)" in
		*64)
			;;
		*)
			cat >&2 <<-'EOF'
			     ----------------------------------
			        Error: you are using a 32 bit kernel.
			        Lacework currently only supports 64bit platforms.
			     ----------------------------------
			EOF
			exit 200
			;;
	esac
}

check_root_cert() {

	echo "Check Go Daddy root certificate"
mypid=$$
cat >/tmp/${mypid}.cert <<-'EOF'
-----BEGIN CERTIFICATE-----
MIIEfTCCA2WgAwIBAgIDG+cVMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT
MSEwHwYDVQQKExhUaGUgR28gRGFkZHkgR3JvdXAsIEluYy4xMTAvBgNVBAsTKEdv
IERhZGR5IENsYXNzIDIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMTAx
MDcwMDAwWhcNMzEwNTMwMDcwMDAwWjCBgzELMAkGA1UEBhMCVVMxEDAOBgNVBAgT
B0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHku
Y29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRpZmljYXRlIEF1
dGhvcml0eSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv3Fi
CPH6WTT3G8kYo/eASVjpIoMTpsUgQwE7hPHmhUmfJ+r2hBtOoLTbcJjHMgGxBT4H
Tu70+k8vWTAi56sZVmvigAf88xZ1gDlRe+X5NbZ0TqmNghPktj+pA4P6or6KFWp/
3gvDthkUBcrqw6gElDtGfDIN8wBmIsiNaW02jBEYt9OyHGC0OPoCjM7T3UYH3go+
6118yHz7sCtTpJJiaVElBWEaRIGMLKlDliPfrDqBmg4pxRyp6V0etp6eMAo5zvGI
gPtLXcwy7IViQyU0AlYnAZG0O3AqP26x6JyIAX2f1PnbU21gnb8s51iruF9G/M7E
GwM8CetJMVxpRrPgRwIDAQABo4IBFzCCARMwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDqahQcQZyi27/a9BUFuIMGU2g/eMB8GA1Ud
IwQYMBaAFNLEsNKR1EwRcbNhyz2h/t2oatTjMDQGCCsGAQUFBwEBBCgwJjAkBggr
BgEFBQcwAYYYaHR0cDovL29jc3AuZ29kYWRkeS5jb20vMDIGA1UdHwQrMCkwJ6Al
oCOGIWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20vZ2Ryb290LmNybDBGBgNVHSAEPzA9
MDsGBFUdIAAwMzAxBggrBgEFBQcCARYlaHR0cHM6Ly9jZXJ0cy5nb2RhZGR5LmNv
bS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAWQtTvZKGEacke+1bMc8d
H2xwxbhuvk679r6XUOEwf7ooXGKUwuN+M/f7QnaF25UcjCJYdQkMiGVnOQoWCcWg
OJekxSOTP7QYpgEGRJHjp2kntFolfzq3Ms3dhP8qOCkzpN1nsoX+oYggHFCJyNwq
9kIDN0zmiN/VryTyscPfzLXs4Jlet0lUIDyUGAzHHFIYSaRt4bNYC8nY7NmuHDKO
KHAN4v6mF56ED71XcLNa6R+ghlO773z/aQvgSMO3kwvIClTErF0UZzdsyqUvMQg3
qm5vjLyb4lddJIGvl5echK1srDdMZvNhkREg5L4wn3qkKQmw4TRfZHcYQFHfjDCm
rw==
-----END CERTIFICATE-----
EOF
        reqsubstr="OK"

	if command_exists awk; then
	       if command_exists openssl; then
			cert_path=`openssl version -d | grep OPENSSLDIR | awk -F: '{print $2}' | sed 's/"//g'`
			if [ -z "${cert_path}" ]; then
				cert_path="/etc/ssl"
			fi
			cert_ok=`openssl verify -x509_strict /tmp/${mypid}.cert`
			if [ ! -z "${cert_ok##*$reqsubstr*}" ]
			then
				openssl x509 -noout -in /tmp/${mypid}.cert -pubkey > /tmp/lw-installer.key
				cert_ok=`awk -v cmd='openssl x509 -noout -pubkey | cmp -s /tmp/lw-installer.key; if [ $? -eq 0 ]; then echo "installed"; fi' '/BEGIN/{close(cmd)};{print | cmd}' < ${cert_path}/certs/ca-certificates.crt`
				if [ "${cert_ok}" != "installed" ]
				then
					cat >&2 <<-'EOF'
					----------------------------------
						Error: this installer requires Go Daddy root certificate to be installed
						Please ensure the root certificate is installed and retry.
					----------------------------------
					EOF
					if [ "${STRICT_MODE}" = "yes" ]; then
						exit 300
					fi
				else
					rm /tmp/lw-installer.key
				fi
			fi
		fi
	fi
	rm /tmp/${mypid}.cert
}

check_lw_connectivity() {
lw_cfg_url="https://api.lacework.net/upgrade/?name=datacollector&version=${version}"

	echo "Check connectivity to Lacework server"
	if command_exists awk; then
		if [ -f /var/lib/lacework/config/config.json ]
		then
			config_url=`grep -v "#" /var/lib/lacework/config/config.json | awk 'match($0, /serverurl([^,]+)/) { print substr( $0, RSTART, RLENGTH )}'`
			if [ ! -z "${config_url}" ]; then
				config_url=`echo $config_url | sed 's/"//g' | awk -F: '{print $2":"$3}'`
				if [ ! -z "${config_url}" ]; then
					lw_cfg_url="${config_url}"
				fi
			fi
		fi
		if command_exists curl; then
			response=`curl -o /dev/null -w "%{http_code}" -sSL ${lw_cfg_url}`
		elif command_exists wget; then
			response=`wget -vO- ${lw_cfg_url} 2>&1 | grep HTTP | awk '{print $(NF-1)}'`
		elif command_exists busybox && busybox --list-modules | grep -q wget; then
			response="500"
			busybox wget -O- ${lw_cfg_url} 2>&1 > /dev/null
			if [ $? == 0 ]; then
				response="200"
			fi
		fi
		if [ "${response}" != "200" ]; then
			cat >&2 <<-'EOF'
			----------------------------------
			Error: this installer needs the ability to contact $lw_cfg_url
			Please ensure this machine is able to connect to the network
			and/or requires correct proxy settings
			----------------------------------
			EOF
			if [ "${STRICT_MODE}" = "yes" ]; then
				exit 400
			fi
		fi
	fi
}

shell_prefix() {
	user="$(id -un 2>/dev/null || true)"

	if [ "$user" != 'root' ]; then

#		cat >&2 <<-'EOF'
#		This installer needs to run as root. 
#			We are unable to find either "sudo" or "su" available to make this happen.
#		EOF
#		if command_exists sudo; then
#			sh_c='sudo -E sh -c'
#			($sh_c 'echo Using sudo')
#		else
			cat >&2 <<-'EOF'
			     ----------------------------------
			        Error: this installer needs the ability to run commands as root.
			        Please run as root or with sudo
			     ----------------------------------
			EOF
			exit 500
#		fi
	fi
}

get_curl() {
	if command_exists curl; then
		curl='curl -sSL'
	elif command_exists wget; then
		curl='wget -qO-'
	elif command_exists busybox && busybox --list-modules | grep -q wget; then
		curl='busybox wget -qO-'
	fi
}

get_lsb_dist() {

	# perform some very rudimentary platform detection

	case "$usedocker" in
		yes)
			lsb_dist="usedocker"
			;;
		*)
			;;
	esac

	if [ -z "$lsb_dist" ] && command_exists lsb_release; then
		lsb_dist="$(lsb_release -si)"
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/lsb-release ]; then
		lsb_dist="$(. /etc/lsb-release && echo "$DISTRIB_ID")"
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/debian_version ]; then
		lsb_dist='debian'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/fedora-release ]; then
		lsb_dist='fedora'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/oracle-release ]; then
		lsb_dist='oracleserver'
	fi
	if [ -z "$lsb_dist" ]; then
		if [ -r /etc/centos-release ] || [ -r /etc/redhat-release ]; then
			lsb_dist='centos'
		fi
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/os-release ]; then
		lsb_dist="$(. /etc/os-release && echo "$ID")"
	fi
 	if [ -z "$lsb_dist" ] && [ -r /etc/system-release ]; then
 		lsb_dist="$(cat /etc/system-release | cut -d " " -f 1)"
 	fi

	# Convert to all lower
	lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"
}

check_user_x64() {
	case "$lsb_dist" in
		*ubuntu*|*debian*)
			case "$(dpkg --print-architecture)" in
				*64)
					;;
				*)
					cat >&2 <<-'EOF'
					     ----------------------------------
					        Error: Package manager (dpkg) does not support 64bit binaries.
					        Lacework currently only supports 64bit platforms.
					     ----------------------------------
					EOF
					exit 600
					;;
			esac
		;;
		*coreos*|usedocker)
		;;
		*fedora*|*centos*|*redhatenterpriseserver*|*oracleserver*|*scientific*)
		;;
		*)
		;;
	esac
}

get_dist_version() {
	case "$lsb_dist" in
		*ubuntu*)
			if command_exists lsb_release; then
				dist_version="$(lsb_release --codename | cut -f2)"
			fi
			if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
				dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
			fi
		;;
		*debian*)
			dist_version="$(cat /etc/debian_version | sed 's/\/.*//' | sed 's/\..*//')"
			case "$dist_version" in
				8)
					dist_version="jessie"
				;;
				7)
					dist_version="wheezy"
				;;
			esac
		;;
		*oracleserver*)
			# need to switch lsb_dist to match yum repo URL
			lsb_dist="oraclelinux"
			dist_version="$(rpm -q --whatprovides redhat-release --queryformat "%{VERSION}\n" | sed 's/\/.*//' | sed 's/\..*//' | sed 's/Server*//')"
		;;
		*fedora*|centos*|*redhatenterpriseserver*|*scientific*)
			dist_version="$(rpm -q --whatprovides redhat-release --queryformat "%{VERSION}\n" | sed 's/\/.*//' | sed 's/\..*//' | sed 's/Server*//')"
		;;
		*coreos*|usedocker)
			dist_version="coreos"
		;;
		*)
			if command_exists lsb_release; then
				dist_version="$(lsb_release --codename | cut -f2)"
			fi
			if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
				dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
			fi
		;;
	esac
}


download_pkg() {
	case "$lsb_dist" in
		*ubuntu*|*debian*)
			export pkg_fullname="${pkgname}_${version}_amd64.deb"
			(set -x; $sh_c "rm -f /tmp/${pkg_fullname}")
			(set -x; $curl ${download_url}/${pkg_fullname} > /tmp/${pkg_fullname})
			file_sha1=$(sha1sum /tmp/${pkg_fullname} | cut -d " " -f 1)
			exp_sha1=${deb_sha1}
		;;
		*coreos*|usedocker)
			(set -x; $curl ${download_url}/datacollector.service > /etc/systemd/system/datacollector.service)
		;;
		*)
			export pkg_fullname="${pkgname}-${version}-1.x86_64.rpm"
			(set -x; $sh_c "rm -f /tmp/${pkg_fullname}")
			(set -x; $curl ${download_url}/${pkg_fullname} > /tmp/${pkg_fullname})
			file_sha1=$(sha1sum /tmp/${pkg_fullname} | cut -d " " -f 1)
			exp_sha1=${rpm_sha1}
		;;
	esac
	if [ "${exp_sha1}" != "${file_sha1}" ]; then
		echo "----------------------------------"
		echo "Download sha1 checksum failed, [${exp_sha1}] [${file_sha1}]"
		echo "----------------------------------"
		exit 700
	fi
}

install_pkg() {

	# Run setup for each distro accordingly
	case "$lsb_dist" in
		'opensuse project'|*opensuse*|'suse linux'|sle[sd])
#			(set -x; $sh_c 'sleep 3; zypper -n install libpcap')
			(set -x; $sh_c "sleep 3; zypper -n install /tmp/${pkg_fullname}")
		;;
		*ubuntu*|*debian*)
			export DEBIAN_FRONTEND=noninteractive

			did_apt_get_update=
			apt_get_update() {
				if [ -z "$did_apt_get_update" ]; then
					( set -x; $sh_c 'sleep 3; apt-get -qq update' )
					did_apt_get_update=1
				fi
			}

			# Set +e to make sure we do not fail if these commands fail, but capture the error
                        # On end-of-release versions (E.g. 13.10) apt-get update fails

			set +e
			apt_get_update 
#			( set -x; $sh_c 'sleep 3; apt-get -yqq install libpcap0.8' )
#			if [ "$?" = "100" ];
#			then
#				(set -x; $sh_c 'dpkg -l libpcap0.8')
#				if [ "$?" = "1" ];
#				then
#					cat >&2 <<-'EOF'
#					     apt-get has some unmet dependencies for packages, not related to lacework
#					     'apt-get -f install' needs to be run before install can proceed.
#					     Exiting..
#					EOF
#					exit 1
#				fi
#				echo "libpcap0.8 is already installed"
#			fi
			set -e
			( set -x; $sh_c "sleep 3; dpkg -i /tmp/${pkg_fullname}" )
		;;
		*fedora*|*centos*|*oraclelinux*|*redhatenterpriseserver*|*amzn*|*amazon*|*scientific*)

			if [ "$lsb_dist" = "*fedora*" ] && [ "$dist_version" -ge "22" ]; then
				echo "Using dnf"
				( set -x; $sh_c "sleep 3; dnf -y install /tmp/${pkg_fullname}")
			else
				echo "Using yum"
				( set -x; $sh_c "sleep 3; yum -y install /tmp/${pkg_fullname}")
			fi
		;;
		*coreos*|usedocker)
			(set -x; systemctl stop datacollector.service)
			(set -x; systemctl daemon-reload)
			(set -x; systemctl enable datacollector.service)
			(set -x; systemctl start datacollector.service)
		;;
		*)
		# intentionally mixed spaces and tabs here -- tabs are stripped by "<<-'EOF'",
		# spaces are kept in the output
		cat >&2 <<-'EOF'
		    ----------------------------------
		      Error: Your platform is not supported by this installer script.
		    ----------------------------------
		EOF
		exit 1
		;;
	esac
}

# Customized parameters
get_config() {

	if [ ! -f /var/lib/lacework/config/config.json ]
	then
		if [ "$ARG1" = "" ];
		then
			read -p "Please enter access token: " access_token
		else
			access_token=$ARG1
		fi
		if [ "$access_token" = "" ];
		then
			echo "Not a valid access_token"
			exit 800
		fi
		echo "Using access token : $access_token"
		echo "Writing configuration file"

		(set -x; $sh_c 'mkdir -p /var/lib/lacework/config')
		($sh_c 'echo "+ sh -c Writing config.json in /var/lib/lacework/config"')
		($sh_c "echo \"{\" > /var/lib/lacework/config/config.json")
		($sh_c "echo \" \\\"tokens\\\" : { \\\"AccessToken\\\" : \\\"${access_token}\\\" } \"    >> /var/lib/lacework/config/config.json")
		($sh_c "echo \"}\" >> /var/lib/lacework/config/config.json")
	else
		echo "Skipping writing config since a config file already exists"
	fi
}


do_install() {
	check_bash
	check_x64
	
	sh_c='sh -c'
	shell_prefix

	curl=''
	get_curl

	lsb_dist=''
	get_lsb_dist

	check_lw_connectivity

	check_root_cert

	check_user_x64

	dist_version=''
	get_dist_version

	# Check if this is a forked Linux distro
	check_forked

	echo "Installing on  $lsb_dist ($dist_version)"

	get_config

	pkg_fullname=''
	download_pkg
	install_pkg

	echo "Lacework successfully installed"
}

# wrapped up in a function so that we have some protection against only getting
# half the file during "curl | sh"
while getopts "SOh" arg; do
  case $arg in
    h)
	cat >&2 <<-'EOF'
	     ----------------------------------
	     Usage: sudo install.sh -h [-S] [-O]
	            -h: usage banner
	                [Optional Parameters]
	            -S: enable strict mode
	            -O: filter auditd related messages going to system journal
	     ----------------------------------
	EOF
	exit 0
     ;;
    O)
      SYSTEMD_OVERRIDE=yes
      shift
      ;;
    S)
      STRICT_MODE=yes
      shift
      ;;
  esac
done
ARG1=93fa0e075bf1702f3d67017309c3ada6d3b7cb1746237cae6639a831
do_install
if [ "${SYSTEMD_OVERRIDE}" = "yes" ]; then
	if command_exists systemctl; then
	        systemctl mask systemd-journald-audit.socket
	        systemctl restart systemd-journald
	fi
fi
exit 0
