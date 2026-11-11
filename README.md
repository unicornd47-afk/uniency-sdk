# uniency Universal SDK (Rust)

Private design snapshot of the uniency Universal SDK core.

**Status:** design and MVP criteria only. No crate source has been written yet. This repository is private and is not a public release.

## Licence

Dual-licensed under **Apache-2.0 OR MIT**, at the user's option. See `LICENSE-APACHE` and `LICENSE-MIT`.

## What this repository is

The core is specified as a clean-room Rust implementation with its own wire and signature formats. CEWP and CIRIS stay out of this tree: they belong in the separate AGPL adapter repository (`uniency-cewp-adapter`), behind an IPC process boundary.

Intended core scope (from the discussion draft):

- identity (keys, bound hybrid sign/verify, rotation and revocation)
- login challenge-response
- a stable agent API (message and tool-call types, capability tokens)
- a halt/stop primitive that is itself a signed row
- a local trace/telemetry format

A local model runtime is out of core and would be an optional adapter later.

## What is in this snapshot

| Path | Role |
| --- | --- |
| `SDK_DISCUSSION.md` | Crate-structure and design discussion (draft) |
| `MVP_CRITERIA.md` | Measurable MVP criteria (draft; targets, not measured results) |

No Rust crates, no `src_ref/` CIRIS or CEWP reference trees, and no `ciris-*` / `cewp-*` dependencies are included. Those reference trees are AGPL and must not be copied into this repository.

## Bound hybrid (design)

The planned construction is a bound hybrid signature: Ed25519 over the prefixed message, and ML-DSA-65 over `data || ed_sig`. Acceptance requires both halves to verify and the key not to be revoked. The ML-DSA backend intended for the MVP is the RustCrypto `ml-dsa` crate, pinned exactly, with its own wire format (not CIRIS's placeholder codec).

## Related private repositories

- `uniency-cewp-adapter` — separate AGPL service that may speak CIRIS/CEWP over IPC
- `uniency-business` — claims ledger, evidence notes, and partner-chapter drafts
