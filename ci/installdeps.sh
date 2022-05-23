#!/bin/bash
set -xeuo pipefail
apt update -y
apt install -y linux-source flex bison openssl{,-dev}
cd /usr/src
src=$(ls /usr/src/linux-source*.tar*)
bn=$(basename ${src})
d=${bn%.tar*}
if test '!' -d linux; then
    tar xf "${src}"
    cd "${d}"
    make olddefconfig
    make modules_prepare
    cd -
    mv ${d} linux
fi
