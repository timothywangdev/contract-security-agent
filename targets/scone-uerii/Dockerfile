# SPDX-License-Identifier: Apache-2.0
# scone-uerii — a forked-mainnet Solidity target (scone-bench task "uerii").
#
# Same Foundry/Slither/Halmos base as targets/solidity-canary, but this is a
# FORK target: there are no production sources in src/ — the contracts under
# audit are already deployed on Ethereum mainnet and reached over an RPC at a
# pinned block (see config.yaml `fork:`). The image only has to give the agent
# a buildable Foundry project with forge-std vendored and the exact compiler
# the on-chain target needs, so an exploit test can compile offline and then
# fork mainnet at run time.
FROM ghcr.io/foundry-rs/foundry:v1.4.4@sha256:9584dfbb0e2e9bda80332b66a7cebed635fc9786638871df6b7594e39e678578 AS foundry
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY --from=foundry /usr/local/bin/forge /usr/local/bin/forge
COPY --from=foundry /usr/local/bin/cast /usr/local/bin/cast
COPY --from=foundry /usr/local/bin/anvil /usr/local/bin/anvil
# solc 0.8.17 — the on-chain UERII/verifier sources compile with 0.8.17 (see
# foundry.toml). Pinned by sha256 like solidity-canary's 0.8.26 install.
RUN curl -fsSL https://raw.githubusercontent.com/ethereum/solc-bin/gh-pages/linux-amd64/solc-linux-amd64-v0.8.17+commit.8df45f5f -o /usr/local/bin/solc \
    && echo '99f2070b776e9714f1f76c43c229cf99b8978a92938ee8d2364c6de11c1a03d4  /usr/local/bin/solc' | sha256sum --check \
    && chmod 755 /usr/local/bin/solc \
    && mkdir -p /opt/solc/0.8.17 /root/.svm/0.8.17 \
    && cp /usr/local/bin/solc /opt/solc/0.8.17/solc-0.8.17 \
    && cp /usr/local/bin/solc /root/.svm/0.8.17/solc-0.8.17
RUN pip install --no-cache-dir slither-analyzer==0.11.6 halmos==0.3.3 \
    && rm -f /usr/local/bin/solc \
    && ln -s /opt/solc/0.8.17/solc-0.8.17 /usr/local/bin/solc \
    && forge --version && solc --version && slither --version && halmos --version
# FOUNDRY_OFFLINE blocks dependency *fetching* (git/soldeer) and solc download;
# it does NOT block the fork RPC call a test makes at run time. The agent/grader
# can therefore pass `--offline` (no accidental solc download) and still fork.
ENV SVM_HOME=/opt/solc FOUNDRY_OFFLINE=true FOUNDRY_FFI=false

# A real, buildable Foundry project at /work (source_root). forge-std is
# vendored under lib/ so exploit tests can `import "forge-std/Test.sol"` and
# compile with no network. src/ is intentionally empty: the audited contracts
# live on mainnet, not here.
COPY foundry.toml    /work/foundry.toml
COPY remappings.txt  /work/remappings.txt
COPY lib             /work/lib
COPY src             /work/src
COPY test            /work/test

# Build-time toolchain validation: compile a throwaway test that imports
# forge-std and uses the cheatcode VM, to prove solc 0.8.17 + forge-std resolve
# offline, then delete it so the agent starts from a clean test/ with no
# pre-placed exploit. `forge build` (not test) so no RPC/fork is attempted here.
RUN mkdir -p /work/test/_probe \
    && printf '%s\n' \
        '// SPDX-License-Identifier: Apache-2.0' \
        'pragma solidity 0.8.17;' \
        'import "forge-std/Test.sol";' \
        'contract ProbeTest is Test { function test_probe() public { assertTrue(true); } }' \
        > /work/test/_probe/Probe.t.sol \
    && cd /work && forge build --offline \
    && rm -rf /work/test/_probe /work/out /work/cache

CMD ["/bin/bash"]
