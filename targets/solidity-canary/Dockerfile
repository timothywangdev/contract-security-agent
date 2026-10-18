# SPDX-License-Identifier: Apache-2.0
# Foundry + Solidity + Slither + Halmos base (same pins as
# docker/Dockerfile.tools), with the canary's own Foundry project COPYd in at
# /work so source_root is a real, buildable project at image-build time.
FROM ghcr.io/foundry-rs/foundry:v1.4.4@sha256:9584dfbb0e2e9bda80332b66a7cebed635fc9786638871df6b7594e39e678578 AS foundry
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
RUN curl -fsSL https://raw.githubusercontent.com/ethereum/solc-bin/gh-pages/linux-amd64/solc-linux-amd64-v0.8.26+commit.8a97fa7a -o /usr/local/bin/solc \
    && echo 'd5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef  /usr/local/bin/solc' | sha256sum --check \
    && chmod 755 /usr/local/bin/solc \
    && mkdir -p /opt/solc/0.8.26 /root/.svm/0.8.26 \
    && cp /usr/local/bin/solc /opt/solc/0.8.26/solc-0.8.26 \
    && cp /usr/local/bin/solc /root/.svm/0.8.26/solc-0.8.26
RUN pip install --no-cache-dir slither-analyzer==0.11.6 halmos==0.3.3 \
    && rm -f /usr/local/bin/solc \
    && ln -s /opt/solc/0.8.26/solc-0.8.26 /usr/local/bin/solc \
    && forge --version && solc --version && slither --version && halmos --version
ENV SVM_HOME=/opt/solc FOUNDRY_OFFLINE=true FOUNDRY_FFI=false

# COPY the canary's own Solidity source — local COPY, no git-clone (no
# upstream; this is a local-only fixture, same convention as targets/canary).
COPY foundry.toml /work/foundry.toml
COPY src  /work/src
COPY test /work/test

RUN cd /work && forge build --offline

CMD ["/bin/bash"]
