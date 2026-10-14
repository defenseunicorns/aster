# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG ASTER_LAN_BASE_IMAGE=rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97

FROM ${ASTER_LAN_BASE_IMAGE} AS build
ENV PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY third-party ./third-party
RUN cargo build --locked --release \
    -p aster-node -p aster-agent -p asterctl \
    --features aster-node/nearby-discovery,aster-agent/nearby-discovery

FROM ${ASTER_LAN_BASE_IMAGE} AS runtime
ENV PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp
COPY lab/debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update \
    && apt-get install --yes --no-install-recommends python3 \
    && install -d -m 0755 /usr/share/licenses/aster \
    && dpkg-query -W -f='${binary:Package}\t${Version}\n' python3 \
        > /usr/share/licenses/aster/runtime-package-inventory.tsv \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /work/target/release/aster /usr/local/bin/aster
COPY --from=build /work/target/release/aster-agent /usr/local/bin/aster-agent
COPY --from=build /work/target/release/asterctl /usr/local/bin/asterctl
COPY tools/aster_lan_mvp.py /usr/local/libexec/aster/aster_lan_mvp.py
COPY docker/lan-mvp/agent-entrypoint.sh /usr/local/libexec/aster/agent-entrypoint.sh
COPY docker/lan-mvp/init-state.sh /usr/local/libexec/aster/init-state.sh
COPY docker/lan-scale/init-state.sh /usr/local/libexec/aster/init-scale-state.sh
COPY LICENSE /usr/share/licenses/aster/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/licenses/aster/THIRD_PARTY_NOTICES.md
RUN chmod 0755 \
    /usr/local/bin/aster \
    /usr/local/bin/aster-agent /usr/local/bin/asterctl \
    /usr/local/libexec/aster/aster_lan_mvp.py \
    /usr/local/libexec/aster/agent-entrypoint.sh \
    /usr/local/libexec/aster/init-state.sh \
    /usr/local/libexec/aster/init-scale-state.sh
WORKDIR /opt/aster
USER 10001:10001
CMD ["/usr/local/bin/aster-agent", "--help"]
