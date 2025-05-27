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
		sed -i -e "/PBS_INTERACTIVE_.*_ARCH='arch=/s/arch=/select=1:arch=/" /opt/nisp/enginframe/*/enginframe/plugins/pbs/conf/ef.pbs.conf

		# append domain to node names
		[ ! -f /opt/nisp/nat.conf ] || ln -sfn /opt/nisp/nat.conf /opt/nisp/enginframe/conf/plugins/interactive/nat.conf
	else
		echo "Unsupported scheduler"
		exit 1
	fi

	passwd="$(jetpack config ef.admin_password)"
	echo -e "${passwd}\n${passwd}" | sudo passwd efadmin
fi

is_enabled_sku() {
	sku=$(/opt/pbs/bin/pbsnodes $(hostname) | grep vm_size | cut -d= -f2 | cut -d" " -f2)
	jetpack config ef.limit_execute_skus notfound --json | \
	       sed -e 's,"notfound",[],' | \
	       jq '."ef.limit_execute_skus"' | \
	       jq --arg sku "$sku" -e '. == [] or contains([$sku])' >/dev/null
}

if is_compute && is_enabled_sku ; then
	# microsoft docker conflicts with gui server
	! rpm -q moby-runc >/dev/null 2>&1 || dnf remove -y moby-runc

	# relax package pinning enough for EF to install (kmod-kvdo)
	sed -i -e "s, kmod\\* , kmod-iser* kmod-knem* kmod-mlnx-* kmnod-srp* ,g" /etc/dnf/dnf.conf

	# only Microsoft-modified NVIDIA grid driver has this config file
	if ! [ -f /etc/nvidia/gridd.conf ] ; then
		nv=$(mktemp)
		wget -O $nv https://go.microsoft.com/fwlink/?linkid=874272
		chmod +x $nv
		$nv -s
		rm -f $nv

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

	wget --quiet -O dcv_installer.sh https://raw.githubusercontent.com/NISP-GmbH/DCV-Installer/refs/heads/main/DCV_Installer.sh
	sed -i -e "s,[[:space:]]centosSetupNvidiaDriver,true," \
		-e "s,sudo yum upgrade,#sudo yum upgrade," \
		-e "s,sudo yum -y update,#sudo yum -y update," \
		dcv_installer.sh
	bash dcv_installer.sh --without-interaction --dcv_server_install=true --dcv_server_gpu_nvidia=true

	sed -i -e '/#auth-token-verifier=/s,.*,auth-token-verifier="http://127.0.0.1:8444",' \
		-e "s,create-session = true,create-session = false," \
		/etc/dcv/dcv.conf

	systemctl restart dcvserver

	systemctl enable --now dcvsimpleextauth.service
	systemctl restart dcvsimpleextauth.service
fi
