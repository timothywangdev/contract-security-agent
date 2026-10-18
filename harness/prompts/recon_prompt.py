# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Recon-agent prompt. Explores a target's source tree and proposes a partition
of the attack surface into focus areas for parallel find-agents.

Output format matches targets/*/config.yaml focus_areas: — one descriptive
string per subsystem, self-contained enough to hand directly to a find-agent.
"""

RECON_PROMPT_TEMPLATE = """\
You are a recon agent supporting an authorized security research engagement.
Your job is to partition a codebase's attack surface into focus areas for
parallel vulnerability hunters.

## Environment

You are running inside an isolated sandbox with the target source. Explore directly.

- Source root: {source_root}
{binary_line}- Project: {github_url} @ {commit}

## Task

Identify 5–15 distinct contracts or modules that handle untrusted input or
value transfer. Each will be assigned to one find-agent for a deep-dive. They
need to be independent enough that N agents working in parallel won't
converge on the same findings.

**Good partitions** — different contracts, different responsibilities, different
trust boundaries. Example: ERC20 token module vs staking/rewards module vs
governance module.

**Bad partitions** — too narrow ("one line in one function"), too broad ("all
of accounting"), or overlapping (two areas that funnel into the same state
transition).

## Exploration

1. List the source tree: `find {source_root} -type f -name '*.sol'`
2. Read entry points and dispatch code — look for external/public functions,
   access-control modifiers, state-variable layout, and external calls
   (other contracts, tokens, oracles).
3. For each subsystem: note the contract/function-name pattern or file, and
   what operations it performs (share accounting, reward distribution,
   privileged parameter changes, external-call sequencing, etc). These hints
   steer the find-agent toward likely bug classes (reentrancy, access
   control, accounting/share-price manipulation, rounding).

## Output Format

Emit a `<focus_areas>` tag with ONE area per line. Each line is handed
verbatim to a find-agent as "concentrate here", so make it self-contained.

Pattern: `<subsystem name> (<contract/function pattern>) — <key operations>`

Example:
<focus_areas>
ERC20 token module (Token.sol, transfer/transferFrom) — fee-on-transfer accounting, allowance edge cases
Staking/rewards module (Staking.sol, stake/claim/withdraw) — share-price accrual, reward-per-token rounding
Governance module (Governor.sol, propose/vote/execute) — privileged parameter changes, timelock bypass
</focus_areas>

Emit the tag once. Do not send further messages after.
"""


def build_recon_prompt(
    github_url: str,
    commit: str,
    source_root: str,
    binary_path: str,
) -> str:
    binary_line = f"- Entry point: `{binary_path} <input_file>`\n" if binary_path else ""
    return RECON_PROMPT_TEMPLATE.format(
        github_url=github_url,
        commit=commit,
        source_root=source_root,
        binary_line=binary_line,
    )
