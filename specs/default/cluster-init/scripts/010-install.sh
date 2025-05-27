#!/bin/sh

set -e

function is_slurm() {
    [ $(jetpack config slurm.role not-slurm) != not-slurm ]
}

function is_pbs() {
    [ $(jetpack config pbspro.version not-pbs) != not-pbs ]
}

function is_scheduler() {
    (is_slurm && jetpack config slurm.role | grep -q 'scheduler') || \
    (is_pbs && jetpack config roles | grep -q pbspro_server_role)
}

function is_compute() {
    (is_slurm && jetpack config slurm.role | grep -q 'execute') || \
    (is_pbs && jetpack config roles | grep -q pbspro_execute_role)
}

[ "$(jetpack config ef.install False)" = True ] || exit 0

if is_scheduler && [ ! -d /opt/nisp/enginframe ] ; then
	tmp=$(mktemp -d)
	pushd "$tmp"

	shared=$(jetpack config cyclecloud.mounts.builtinshared.mountpoint)
	cluster=$(jetpack config cyclecloud.cluster.name)
	clusterdir="$shared"/"$cluster"
	mkdir -p "$clusterdir"
	chmod 755 "$clusterdir"
	spooler_dir="$clusterdir"/ef/spoolers
	sessions_dir="$clusterdir"/ef/sessions
	mkdir -p "$spooler_dir" "$sessions_dir"

	wget --quiet -O efinstall.config https://www.ni-sp.com/wp-content/uploads/2019/10/EFP-Download/efinstall.config
	sed -i -e "/^ef.spooler.dir = /s,.*,ef.spooler.dir = $spooler_dir," \
		-e "/^ef.sessions.dir = /s,.*,ef.sessions.dir = $sessions_dir," \
		-e "/^kernel.java.home = /s,.*,kernel.java.home = /etc/alternatives/jre_11," \
		-e "/pbs.binaries.path = /s,.*,pbs.binaries.path = /opt/pbs/bin," \
		efinstall.config

	wget --quiet -O ef-portal-installer.sh https://raw.githubusercontent.com/NISP-GmbH/EF-Portal-Installer/refs/heads/main/ef-portal-installer.sh
	sed -i -e "s,--no-check-certificate,,g" \
		-e "s,[[:space:]]prepareEnvironment,#,g" \
		-e "s,wget.*\\\$JAVA_,true ,g" \
		-e "s,tar.*\\\$JAVA_,true ,g" \
		-e "s,export JAVA_HOME=.*umask,umask,g" \
		ef-portal-installer.sh

	rpm -q java-11 >/dev/null 2>&1 || dnf install -y java-11

	jetpack config ef.license | base64 -d > license.ef

	if is_slurm ; then
		EF_PORTAL_CONFIG_NAME=efinstall.config bash ef-portal-installer.sh --slurm_support=true --license_file=license.ef --https_port=8448

		# add arch option to slurm?
	elif is_pbs ; then
		# switch slurm support to pbs
		sed -i -e "s/slurm/pbs/g" ef-portal-installer.sh

		sed -i -e "/pbs.binaries.path = /s,.*,pbs.binaries.path = /opt/pbs/bin," efinstall.config

		EF_PORTAL_CONFIG_NAME=efinstall.config bash ef-portal-installer.sh --pbs_support=true --license_file=license.ef --https_port=8448

		# autoscale.py seems to do that automatically
		#/opt/pbs/bin/qmgr -c "list resource arch" >/dev/null  2>/dev/null || \
		#	/opt/pbs/bin/qmgr -c "create resource arch type=string h"

		# add arch resource for EF
		tmp=$(mktemp)
		asjson=/opt/cycle/pbspro/autoscale.json
		jq '.default_resources = [.default_resources[] | select(.name != "arch")] + [{ "select": {}, "name": "arch", "value": "linux" }]' < $asjson > "$tmp"
		cat "$tmp" > $asjson
		rm "$tmp"

		# switch to new style resource requests to we can use pack and excl
		sed -i -e "/PBS_INTERACTIVE_.*_ARCH='arch=/s/arch=/select=1:arch=/" \
			/opt/nisp/enginframe/*/enginframe/plugins/pbs/conf/ef.pbs.conf

		# append domain to node names
		[ ! -f /opt/nisp/nat.conf ] || ln -sfn /opt/nisp/nat.conf \
			/opt/nisp/enginframe/conf/plugins/interactive/nat.conf

		# submit from spooler so that .e/.o files can be copied back on
		# session termination
		sed -i -e '/^touch "\${interactive_sessionDir}/icd "${interactive_sessionDir}"' \
			/opt/nisp/enginframe/*/enginframe/plugins/pbs/interactive/interactive.submit
	else
		echo "Unsupported scheduler"
		exit 1
	fi

	passwd="$(jetpack config ef.admin_password)"
	echo -e "${passwd}\n${passwd}" | sudo passwd efadmin

	server_pkcs12=$(jetpack config ef.server_pkcs12_file "")
	server_pkcs12_password=$(jetpack config ef.server_pkcs12_password "")
	if [ -n "$server_pkcs12" -a -n "$server_pkcs12_password" ] ; then
		# cat server.key server.crt | openssl pkcs12 -export -name ef | base64 -w 0
		echo "$server_pkcs12" | base64 -d > server.p12
		keystore=/opt/nisp/enginframe/conf/tomcat/conf/certs/ef.tomcat.keystore
		storepass=$(cat /opt/nisp/enginframe/conf/tomcat/conf/certs/ef.keystore.password)
		keytool -keystore $keystore -delete -storepass "$storepass" -alias ef || true
		keytool -importkeystore -deststorepass "$storepass" -destkeystore $keystore \
			-destkeypass "$storepass" -srckeystore server.p12 -srcstoretype PKCS12 \
			-srcstorepass "$server_pkcs12_password" -alias ef
		systemctl restart enginframe
	fi

	popd
	rm -rf "$tmp"
fi

is_enabled_sku() {
	sku=$(/opt/pbs/bin/pbsnodes $(hostname) | grep vm_size | cut -d= -f2 | cut -d" " -f2)
	jetpack config ef.limit_execute_skus notfound --json | \
	       sed -e 's,"notfound",[],' | \
	       jq '."ef.limit_execute_skus"' | \
	       jq --arg sku "$sku" -e '. == [] or contains([$sku])' >/dev/null
}

if is_compute && is_enabled_sku ; then
	tmp=$(mktemp -d)
	pushd "$tmp"

	# add swap space for increased responsiveness and fluid interactive work
	touch /mnt/swap1
	chmod 600 /mnt/swap1
	diskavail=$(df -k --output=avail /mnt/swap1 | tail -n 1)

	# use half the disk space but cap it to the RAM size
	swapsize=$((diskavail / 2))
	memtotal=$(grep ^MemTotal: /proc/meminfo | sed -e "s,.*:[[:space:]]*\\([[:digit:]]\\+\\) kB.*,\\1,")
	[ "$swapsize" -lt "$memtotal" ] || swapsize="$memtotal"

	fallocate -l "$((swapsize * 1024))" /mnt/swap1
	mkswap /mnt/swap1
	swapon /mnt/swap1
	# TODO: make reboot-safe, with conflict with use of temporary disk,
	# would need script running at boot creating the swap file

	# microsoft docker conflicts with gui server
	! rpm -q moby-runc >/dev/null 2>&1 || dnf remove -y moby-runc

	# relax package pinning enough for EF to install (kmod-kvdo)
	sed -i -e "s, kmod\\* , kmod-iser* kmod-knem* kmod-mlnx-* kmnod-srp* ,g" /etc/dnf/dnf.conf

	# only Microsoft-modified NVIDIA grid driver has this config file
	if ! [ -f /etc/nvidia/gridd.conf.template ] ; then
		nv=$(mktemp)
		wget -O $nv https://go.microsoft.com/fwlink/?linkid=874272
		chmod +x $nv
		$nv -s
		rm -f $nv
	fi

	# module may not be present for running kernel if upgraded during image
	# build before installing the driver
	if ! [ -f /lib/modules/$(uname -r)/extra/nvidia.ko.xz ] ; then
		mod=$(dkms status -m nvidia | head -1 | cut -d, -f1)
		dkms install "$mod"
	fi

	if ! [ -f /etc/nvidia/gridd.conf ] ; then
		cp -f /etc/nvidia/gridd.conf.template /etc/nvidia/gridd.conf
		cat <<EOF >>/etc/nvidia/gridd.conf
IgnoreSP=FALSE
EnableUI=FALSE
EOF
		sed -i '/FeatureType=0/d' /etc/nvidia/gridd.conf

		systemctl restart nvidia-gridd
	fi

	cat << EOF >>/etc/sysctl.d/net.conf
	net.core.rmem_max=2097152
	net.core.wmem_max=2097152
EOF

	sysctl -f /etc/sysctl.d/net.conf

	rpm -q epel-release >/dev/null 2>&1 || dnf install -y epel-release
	dnf grouplist --installed | grep -i "xfce" || dnf groupinstall -y xfce

	if ! [ -f /etc/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-screensaver.xml ] ; then
		cat <<EOF >/etc/xdg/xfce4/xfconf/xfce-perchannel-xml/xfce4-screensaver.xml
<?xml version="1.0" encoding="UTF-8"?>

<channel name="xfce4-screensaver" version="1.0">
  <property name="lock" type="empty">
    <property name="enabled" type="bool" value="false" unlocked="root"/>
  </property>
</channel>
EOF
	fi

	cat <<EOF >/etc/rc.d/rc3.d/busidupdate.sh
#!/bin/bash
BUSID=\$(nvidia-xconfig --query-gpu-info | awk '/PCI BusID/{print \$4}')
nvidia-xconfig --enable-all-gpus --allow-empty-initial-configuration -c /etc/X11/xorg.conf --virtual=1920x1200 --busid \$BUSID -s
sed -i '/BusID/a\ Option "HardDPMS" "false"' /etc/X11/xorg.conf
EOF
chmod +x /etc/rc.d/rc3.d/busidupdate.sh
/etc/rc.d/rc3.d/busidupdate.sh

	systemctl stop dcvserver || true

	dnf grouplist --installed | grep -i "Server with GUI" || dnf groupinstall -y "Server with GUI"

	cat <<-EOF >dcvrpmkey
		-----BEGIN PGP PUBLIC KEY BLOCK-----
		Version: GnuPG v2.0.22 (GNU/Linux)

		mQENBFnObokBCAColwxCCvgj2KniCq4pqh9REGj6CjaOUYcUFSlf+eCwcNhaUWAx
		+49rkkEWtcc/uJEE4ZL+q+r3imoH8KHFr8HBsi10xktPohxdhvKtEcG9EZIFH1zC
		xmTZCab7jrz54rZvc1+tGlmjhQLIQSVros7Sfq6ufNPz/eCj1wTU5o9JIrie87sG
		rciY408EOfHstJOE8Esa24IDJg+/dF/CxoAi77cKadqNNWq4z1rzF8ngJPLybbaS
		GxYnIbLr+0hq8Orlb/jQIenrlYSJrKQPVuPRwA7JUpxwNWCnjh32vC9/pjTXh0W5
		FXLy2PsJClXnzSNIaqHdgs6rJZjep55EtrZ9ABEBAAG0J05JQ0Ugcy5yLmwuIDxz
		dXBwb3J0QG5pY2Utc29mdHdhcmUuY29tPokBVAQTAQgAPgIbAwULCQgHAgYVCAkK
		CwIEFgIDAQIeAQIXgBYhBFue68hkRJcB9s5WahG1xwoXDGEUBQJlHrl6BQkPErHx
		AAoJEBG1xwoXDGEUvHUIAIA/lDdXYG940B1OaHc2PKa82E1omJteqh3DNPfDA0Xy
		ZZsAHt2GsNGsfgCDfYuNkSwyqFPC5ZmJ4ejSo9L48vxj/Ccsq7WmzTRxkKd+562y
		hZnIaKsiRlAR0C3WQVcn+OMqPewZFk7WPPnR1Bv99yCe9cVi3DChfSvmztMgcAAT
		JetyMR2z8myoWApOR0j/C/7AcWHd7UvM3j+WXwv21jKlCiZyZsDswe9wG8N5R7rO
		W/SZ0VGS4RH1LR/W5CWXU049DoU/nu2NyDHqUu0asiUJC2sg6sF4LDwstwRBb9UT
		CUhvoYrc8V3GoLyz/gREQ3aPJoTJ5gbe7I6Qme0Mb9S5AQ0EWc5uiQEIALKIH9li
		yci5tXotIX5/NjWSCcLONq8TjYOlEjZvSKE4MCy6acaYTeaJBDXdJxOB+hosqzMv
		NCRv2K+D3YPteJ43LpjdBm9ixJ672N4KoKelcvPKl4A5vF66pr2VQ+0hWt0Gthv8
		HCvvbogeVJ0GE57QKNFVjji2pqkSvW9/znDjlW2qNUP560i72fPVUmyt2iFzlccH
		rfI8FPHe99CeTcpSzCpz4fSj2MlB9OpazdlycUyegiiGqaORWs3vF1/FtcryNM4d
		wgjdXoAH5mFR1+VRhXjxHP19akexxM6XNRSIGz0qlH4iMY6ueBFtLJ+1b4Klxk5S
		St/6TCyqCnUiue0AEQEAAYkBPAQYAQgAJgIbDBYhBFue68hkRJcB9s5WahG1xwoX
		DGEUBQJlHrmFBQkPErH8AAoJEBG1xwoXDGEUMlsH+gLw+y0v+9gt7rFqwRpyHgK/
		hRdQWUP5B3P9QpkS88OPe4A4LI6tBs1ihDv2qexkmb03uFN+rUxwVeRFKDXSGx/b
		qm7ZYTA7/n0WdfVsPUCwbq/+ujBKGOetkLuxwLxXU2yniVsgo33bEzSMtUxtNGW/
		j9tbHeXVqpfOYTf0QETikgJ2d9grh8jRBWxlzkiMN7hpmoogtq9nwt8kGORCDHyj
		WRdTM0VrmWKI9So/D518sRHCrNgeLGct5hfCsUC3WDM/T55iMrfiZYJ3ZPQsJtqk
		dcQers/1L/zzdNlfSAr9C/BsZa2zr+l6Wsw4knAZTy66LFuw0Zv97qO02B/I6/8=
		=Hm4H
		-----END PGP PUBLIC KEY BLOCK-----
	EOF
	rpm --import dcvrpmkey
	rm -f dcvrpmkey

	# do not isolate graphical target to not pull up scheduling system exec
	# daemons prematurely. We only need the gdm to run for GPU acceleration
	# anyway and this is only in case of reboots to get it running then.
	systemctl set-default graphical.target

	cat <<-EOF >>/etc/polkit-1/localauthority/50-local.d/45-allow-colord.pkla
		[Allow Colord all Users]
		Identity=unix-user:*
		Action=org.freedesktop.color-manager.create-device;org.freedesktop.color-manager.create-profile;org.freedesktop.color-manager.delete-device;org.freedesktop.color-manager.delete-profile;org.freedesktop.color-manager.modify-device;org.freedesktop.color-manager.modify-profile
		ResultAny=no
		ResultInactive=no
		ResultActive=yes
	EOF

	cat <<-EOF >/etc/modprobe.d/blacklist.conf
		blacklist vga16fb
		blacklist nouveau
		blacklist rivafb
		blacklist nvidiafb
		blacklist rivatv
	EOF
	rmmod nouveau >/dev/null 2>&1 || true

	dcv_rpms="glx-utils nice-dcv-server nice-xdcv nice-dcv-web-viewer nice-dcv-gl nice-dcv-gltest nice-dcv-simple-external-authenticator"
	dcv_pkgcount=$(echo $dcv_rpms | wc -w)
	if [ "$(rpm -qa $dcv_rpms | wc -l)" -ne $dcv_pkgcount ] ; then
		curl -L -o dcv.tar.gz https://d1uj6qtbmh3dt5.cloudfront.net/nice-dcv-el8-x86_64.tgz
		echo b9d24624b857d4315bcd5d90047d18d4924940153d98828b67ae78521916dd83  dcv.tar.gz | sha256sum -c
		tar -xf dcv.tar.gz

		dnf install -y glx-utils nice-dcv-*x86_64/nice-{dcv-server,xdcv,dcv-web-viewer,dcv-gl,dcv-gltest,dcv-simple-external-authenticator}-*.el8.x86_64.rpm
	fi

	dcv_licserv=$(cat /opt/nisp/dcv-licserv)
	cat <<-EOF > /etc/dcv/dcv.conf
		[display]
		target-fps = 30

		[connectivity]
		enable-quic-frontend = true
		enable-datagrams-display = always-off
		web-port = 8443

		[security]
		no-tls-strict = true
		# no spaces here since grep of detector in job script is broken
		auth-token-verifier="http://127.0.0.1:8444"

		[clipboard]
		primary-selection-paste = true
		primary-selection-copy = true
	EOF

	license="$(jetpack config ef.dcv_license "")"
	if [ -n "$license" ] ; then
		cat <<-EOF >> /etc/dcv/dcv.conf
			[license]
			license-file = "$dcv_licserv"
		EOF
	fi

	dcv_pkcs12=$(jetpack config ef.dcv_pkcs12_file "")
	export dcv_pkcs12_password=$(jetpack config ef.dcv_pkcs12_password "")
	if [ -n "$dcv_pkcs12" -a -n "$dcv_pkcs12_password" ] ; then
		echo "$dcv_pkcs12" | base64 -d > dcv.pkcs12
		openssl pkcs12 -in dcv.pkcs12 -passin env:dcv_pkcs12_password -nodes -nocerts -out /etc/dcv/dcv.key
		openssl pkcs12 -in dcv.pkcs12 -passin env:dcv_pkcs12_password -nokeys -out /etc/dcv/dcv.pem
		chown dcv /etc/dcv/dcv.key /etc/dcv/dcv.pem
		chmod 0600 /etc/dcv/dcv.key /etc/dcv/dcv.pem
	fi

	# restart gdm now after dcv is installed because it installs an xdg
	# autostart item that needs to be run on the login manager console so
	# that GL rendering offload to it works
	sed -i '/^\[daemon\]/a WaylandEnable=false' /etc/gdm/custom.conf
	systemctl restart gdm

	systemctl enable --now dcvserver
	systemctl restart dcvserver

	systemctl enable --now dcvsimpleextauth.service
	systemctl restart dcvsimpleextauth.service

	popd
	rm -rf "$tmp"
fi
