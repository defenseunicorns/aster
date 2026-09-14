# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
# Official docker.io/library/ubuntu:24.04, resolved 2026-09-11.
FROM ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
COPY aster.deb /tmp/aster.deb
# This is a package test: apt runs the package maintainer scripts, resolves
# dependencies, and installs the actual shipped executables. No Rust build.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends python3 /tmp/aster.deb \
    && dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' aster \
    && /usr/bin/aster --help >/dev/null \
    && /usr/bin/aster-agent --help >/dev/null \
    && rm -rf /var/lib/apt/lists/* /tmp/aster.deb
COPY node.py aster_lan_mvp.py /opt/aster-test/
WORKDIR /opt/aster-test
USER aster:aster
ENTRYPOINT ["python3", "/opt/aster-test/node.py"]
