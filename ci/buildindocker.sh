#!/bin/sh

set -e

docker build -f ci/Dockerfile.build -t liblorawan_buildenv .
docker run liblorawan_buildenv sh -c "cd /root/liblorawan && meson builddir && cd builddir && ninja"
