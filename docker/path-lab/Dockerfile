# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG ASTER_PATH_LAB_BASE_IMAGE=rust@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97

FROM ${ASTER_PATH_LAB_BASE_IMAGE}
ENV PATH="/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
RUN install -d -m 0755 /usr/share/licenses/aster
COPY LICENSE /usr/share/licenses/aster/LICENSE
LABEL org.opencontainers.image.source="https://github.com/edgesoftops/astertech" \
      org.opencontainers.image.title="Aster path-lab tools" \
      org.opencontainers.image.description="Pinned generic Linux node for bounded path-lab smoke tests"
CMD ["sleep", "infinity"]
