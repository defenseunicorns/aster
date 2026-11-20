# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG ASTER_HIERARCHY_BASE_IMAGE=rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97

FROM ${ASTER_HIERARCHY_BASE_IMAGE} AS build
ENV PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
RUN cargo build --locked --release \
    -p aster-node \
    --bin aster-hierarchy-demo-node \
    --features aster-node/nearby-discovery

FROM ${ASTER_HIERARCHY_BASE_IMAGE} AS runtime
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HOME=/tmp
COPY --from=build /work/target/release/aster-hierarchy-demo-node \
    /usr/local/bin/aster-hierarchy-demo-node
COPY docker/hierarchy-mvp/demo-node-entrypoint.sh \
    /usr/local/libexec/aster/hierarchy-demo-node-entrypoint.sh
COPY LICENSE /usr/share/licenses/aster/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/licenses/aster/THIRD_PARTY_NOTICES.md
RUN install -d -o 10001 -g 10001 -m 0755 \
        /provision \
    && install -d -o 10001 -g 10001 -m 0700 \
        /state \
        /provision/publisher \
        /provision/bridge-alpha \
        /provision/bridge-bravo \
        /provision/consumer \
        /provision/outsider \
    && chmod 0755 \
        /usr/local/bin/aster-hierarchy-demo-node \
        /usr/local/libexec/aster/hierarchy-demo-node-entrypoint.sh
WORKDIR /opt/aster
USER 10001:10001
ENTRYPOINT ["/usr/local/libexec/aster/hierarchy-demo-node-entrypoint.sh"]
