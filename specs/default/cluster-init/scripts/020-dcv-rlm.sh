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

is_scheduler || exit 0

[ "$(jetpack config ef.install False)" = True ] || exit 0

license="$(jetpack config ef.dcv_license "")"
[ -n "$license" ] || exit 0

d=$(mktemp -d)
pushd "$d"
wget -O rlm.tgz https://reprisesoftware.com/wp-content/uploads/2025/v17-0/rlm.v17.0BL1-x64_l1.admin.tar.gz
echo 5a191b04ababc36a390debbbf0b0790af10f5176e3ef4b2a61d5f8e58ab1fc3e  rlm.tgz | sha256sum -c -

mkdir -p /opt/nisp/rlm/license /var/log/dcv-rlm
tar -xf rlm.tgz -C /opt/nisp/rlm

groupadd -r dcv-rlm
useradd -r -g dcv-rlm -d "/opt/nice/rlm" -s /sbin/nologin -c "RLM License Server" dcv-rlm

chown -R dcv-rlm: /var/log/dcv-rlm

cat <<EOF > /etc/logrotate.d/dcv-rlm
/var/log/dcv-rlm/rlm.log {
    missingok
    nocreate
}
EOF

echo "$license" | base64 -d > /opt/nisp/rlm/license/dcv.lic

# get and install the ISV server
wget -O dcv.tgz https://d1uj6qtbmh3dt5.cloudfront.net/nice-dcv-el8-x86_64.tgz
echo b9d24624b857d4315bcd5d90047d18d4924940153d98828b67ae78521916dd83  dcv.tgz | sha256sum -c

tar -xf dcv.tgz
rpm2cpio nice-dcv-*/nice-dcv-server-*.rpm | cpio -id ./usr/share/dcv/license/nice.set
mv usr/share/dcv/license/nice.set /opt/nisp/rlm

cat <<EOF > /etc/systemd/system/dcv-rlm.service
[Unit]
Description=DCV RLM Server
After=network.target remote-fs.target

[Service]
Type=simple
ExecStart=/opt/nisp/rlm/rlm -c /opt/nisp/rlm/license -nows -dlog +/var/log/dcv-rlm/rlm.log
User=dcv-rlm

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dcv-rlm
systemctl restart dcv-rlm

popd
rm -rf "$d"
