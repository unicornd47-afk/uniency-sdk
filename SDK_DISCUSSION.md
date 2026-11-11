# uniency Universal SDK (Rust): discussion and crate-structure draft

Status: DRAFT, internal. Nothing published. No public CIRIS wording without OK from Gerrit and CIRIS.
Maintained by Kiri. Others add their section below (uni: MVP criteria, PhaseMirror: security model, dahill: consistency/licence, REA: docs/German).
Source read: CIRISAI/CEWP at commit f73b918c324a8705f932d184e24b18755a71dcc7 (local copy src_ref/CEWP). No builds run.

## 0. Facts from the repo that change the plan (please check, dahill)

1. **Licence mismatch inside CEWP.** Root `LICENSE` is GNU AGPL-3.0, but every crate manifest
   (`cewp-kernel`, `cewp-evidence`, `cewp-adversary`, `cewp-cli`, `kernel-wasm`) declares `license = "Apache-2.0"`;
   `cewp-csd4` and `cewp-sim` declare none. Which one applies must be clarified with CIRIS before we link anything.
2. **CEWP has no signature crate.** No CEWP crate depends on Ed25519/ML-DSA libraries. CEWP is the kernel,
   simulation, adversary suite and evidence layer. The actual hybrid signing / wire lives in other CIRIS repos
   named in the README: CIRISEdge (wire, v45), CIRISVerify, CIRISPersist, CIRISServer (fabric node, benchmarks).
   So "dock onto the CEWP crates for login signatures" really means docking onto CIRISVerify (`ciris-crypto`).
   Read since (see CLAIMS_LEDGER S1-S24): Verify ec8c79ee (22.2.0), Edge e3d597cb (44.1.2), Server 7af5d4eb (0.5.245),
   all AGPL-3.0-or-later in Cargo; consumers pin Verify v22.0.0. `HybridSigner` is a **bound** hybrid:
   pqc_sig = ML-DSA-65(data || ed25519_sig), not two independent signatures over the same bytes. No context string
   inside the signer (caller supplies it); `pqc-ml-dsa` is off by default in `ciris-crypto`; `HybridSignature::to_bytes`
   is a placeholder, not a finished CBOR/COSE codec. Ed25519 verify uses `verify_strict`; ML-DSA from `ml-dsa` 0.1.1.
3. Per README: identities and agent charters are hybrid-signed rows (Ed25519 + ML-DSA-65); KEM is X-Wing
   (X25519 + ML-KEM-768); encoding CBOR/COSE. Stated in docs; measured numbers only per EVIDENCE.md.

## 1. Kiri's view on the four points

**Core (what belongs in the kernel):**
- In: identity (keys, hybrid sign/verify, key rotation/revocation), login challenge-response, a stable
  agent API (message/tool-call types, capability tokens), a halt/stop primitive that is itself a signed row,
  local trace/telemetry *format* (structured, signed-optional, local file sink).
- Out of core: local model runtime (GoldWorm) as an optional adapter crate, so the core stays small and
  licence-clean; any network/cloud exporter for telemetry; anything BUSL.

**Architecture:** a Rust workspace with a small, `#![forbid(unsafe_code)]` core and thin adapters (see §2).
Crypto is behind a trait so we can use the CIRIS implementation once licence/API are confirmed, and a
well-known audited crate pair meanwhile. Bindings contain no logic: they only marshal types.

**Licence: DECIDED (b) by Gerrit, 2026-11-11 via mixxy: "Wenn es Lizenzprobleme gibt, nehmen wir unsere eigenen Formate."**
Consequences: core crates carry a permissive SPDX (exact licence, e.g. Apache-2.0 OR MIT, still to be fixed by Gerrit/dahill); our own wire and signature formats (§2b framing); no AGPL crate in the core graph (L1 `cargo deny` + graph test, dahill checks); CEWP/CIRIS only as a separate AGPL service/adapter behind a process boundary. (a) is dropped.

**Under (b), added 2026-11-11 (dahill/PhaseMirror):**
- Core builds the bound hybrid itself from permissive crates: `ed25519-dalek` (BSD-3) + `ml-dsa =0.1.1` (Apache-2.0/MIT, [H] until cargo deny). I1a pins `ml-dsa` directly; the CIRISVerify `rev = cbcd9576` pin applies only to the AGPL adapter.
- Clean room: the core is written from the spec only; no code from `src_ref/` (AGPL) is copied. dahill's review includes a diff check against `src_ref`.
- Own formats are not CIRIS-compatible: the adapter translates, with a roundtrip test per translation and a cross-boundary interop test (core signs / adapter verifies with ciris-crypto and vice versa, mirrored negatives).
- L1 (r10 proposal): deny.toml licence allowlist (MIT, Apache-2.0, BSD-2/3, ISC, Unicode-3.0, Zlib), checked on default and --all-features graphs; `[bans]` on `ciris-*`/`cewp-*`; adapter in its own workspace, absent from `cargo tree -p <core>`.

- (a) Whole core AGPL-3.0-only; CEWP/CIRIS crates linked directly. Consequence: every customer app that links the SDK in-process becomes AGPL on distribution or network use. This is a business-model decision.
- (b) Permissive core (e.g. Apache-2.0); CEWP/CIRIS run as a separate AGPL service behind a process boundary with a documented protocol.
Bindings inherit the licence of the core they link (no thin-layer exception). Every crate carries its SPDX id in Cargo.toml and README.
UtoPiCorn_LM (BUSL-1.1, not GPL-compatible) lives in its own repo/workspace with no shared code, never a dependency or feature of the core; it talks to the SDK only over a process/IPC boundary with a documented protocol. That boundary is also a trust boundary: every request is a hybrid-signed row and passes the halt check before the service acts (negative tests: unsigned, replayed, sent while halted). GoldWorm weights are loaded at runtime only, never in the repo; their licence/data provenance is a separate item. `cargo-deny`
licence allowlist per crate enforces it in CI.

**Local-first / MVP:** everything runs offline on one machine; network is opt-in. Smallest first release =
`uniency-core` + `uniency-identity` + `uniency-login` + the CLI + Python binding, doing: create a hybrid
identity, sign a login challenge, verify it, rotate a key, emit a signed halt, write a local trace. No mesh,
no models, no WASM in v0.1.

## 2. Crate-structure draft

```
uniency-sdk/                     (workspace)
  crates/
    uniency-types       # shared data types, CBOR (de)serialisation, error types; no I/O
    uniency-crypto      # trait HybridSigner/HybridVerifier (Ed25519 + ML-DSA-65); backend feature flags:
                        #   backend-rustcrypto (core default, own formats); NO backend-ciris in-process (AGPL) - CIRIS only via the out-of-process adapter
    uniency-identity    # identity rows, key rotation, revocation list, local keystore (file, OS keyring opt.)
    uniency-login       # challenge-response login on top of identity; server-side verifier + client signer
    uniency-halt        # signed halt/resume rows, halt check inside the tool/model-step dispatch path (poller only as extra abort trigger); halt: any valid signer, resume: Gerrit key only, names halt hash + higher epoch
    uniency-agent       # agent API: messages, tool calls, capability tokens checked against identity
    uniency-trace       # local trace/telemetry format + file sink; exporters behind feature flags (off by default)
    uniency-cewp        # NOT in the core workspace: separate AGPL repo/service (CEWP/CIRIS crates), talks to the core only over a documented IPC/HTTP protocol
    uniency-model-goldworm  # optional local-model adapter (GoldWorm), feature-gated, no network
    uniency-cli         # `uniency id new|sign|verify|rotate|halt|trace`
  bindings/
    py   (PyO3/maturin)   # thin, MVP
    node (napi-rs)        # later
    wasm (wasm-bindgen)   # later; verify-only first (no secret keys in browser at v0.x)
  adapters-external/
    (none)                # utopicorn bridge = separate repo; this workspace holds only the IPC protocol spec
```

Dependency rule: `types <- crypto <- identity <- {login, halt, agent} <- trace`; adapters depend on core,
never the reverse. Bindings depend only on public APIs.

## 2b. Security rules adopted from PhaseMirror (to be implemented in uniency-crypto/identity/halt)
- accept = Ed25519 valid AND ML-DSA-65 valid AND key not revoked AND challenge fresh; anything else rejects.
- Context string (e.g. `uniency/login/v1`) is prepended by our code to `data`. NOTE: CIRIS binds the halves (PQ signs data || Ed25519 sig); if we use `ciris-crypto`, tests must cover that construction (PQ sig valid over wrong classical sig, stripped/replaced Ed25519 half) instead of assuming independent halves. PhaseMirror to confirm.
- Required signature policy lives in the signed identity row, never in the client request; Ed25519-only compat path labelled, time-limited, not client-selectable.
- Server challenge = nonce + audience + expiry, single use.
- Revocation beats rotation; rotation needs both old halves or a recovery key; unknown/stale revocation state rejects.
- Ed25519 `verify_strict`; ML-DSA-65 from a pinned FIPS-204 crate; CIRISVerify interface open until version/licence confirmed.
- Halt: signed row, checked locally before every action, unreadable halt state = halted; agent key can neither lift nor suppress it (lifting needs Gerrit's human key).
- Verification + halt check sit in network-free crates; bindings return only verify results, never key material.
- Negative test set: one half valid, halves swapped, wrong context, reused nonce, revoked key, stale revocation, forged halt, self-signed un-halt.

## 2c. MVP gates
See uni's `MVP_CRITERIA.md` r10.2 (sha de88f176…6ad; core licence Apache-2.0 OR MIT tested over all manifests; option b, permissive-only cargo deny, clean room, A4 adapter; earlier: trybuild, I1a pin; trybuild compile-fail, I1a ml-dsa =0.1.1 pin; length-prefixed ctx framing, trailing-byte reject; bound-hybrid I2, deny.toml clarify for cewp/ciris crates, own versioned wire codec, compile_error! without pqc-ml-dsa; A2b split; answers Q3; Q4: unaudited ML-DSA-65 backend OK for MVP if I1 passes, marked "not audited"). All numbers there are targets, not measurements.

## 3. Open questions
- Q0: DECIDED (b), see §1. Licence of the core: DECIDED by Kiri on Gerrit's delegation ("du entscheidest", 2026-11-11 14:11): `Apache-2.0 OR MIT` (SPDX), LICENSE-APACHE + LICENSE-MIT in every core crate.
- Q1 (dahill/CIRIS): effective licence of CEWP crates (AGPL root vs Apache-2.0 manifests); licences of CIRISEdge/CIRISVerify.
- Q2 (PhaseMirror): halt semantics: who may sign a halt, quorum, how a runtime proves it obeyed; replay protection of login challenges.
- Q3 (uni): MVP metrics (sign/verify latency on laptop + Pi, keystore round-trip, binding overhead, test-vector conformance against CIRIS vectors if they exist).
- Q5: DECIDED (dahill): pin Verify tag v22.0.0 like Edge/Server, add `cargo tree -d` duplicate check to L1; pqc-ml-dsa + ml-dsa =0.1.1 verified only on 22.2.0, unproven for v22.0.0 [H]. Own wire codec until CIRIS replaces to_bytes.
- Q4: interim crypto backend choice and whether its ML-DSA-65 implementation has a public audit (unverified).

## Update 2026-11-11 14:15 (uni): Gerrit chose option b
Gerrit: "Wenn es Lizenzprobleme gibt, nehmen wir unsere eigenen Formate." The core gets its own permissive licence (proposal Apache-2.0 OR MIT, Gerrit decides), its own wire and signature formats (clean-room bound hybrid Ed25519 + ML-DSA-65, own test vectors) and links no AGPL crate. CEWP and CIRIS sit only behind a process boundary in a separate AGPL adapter (`uniency-cewp-adapter`). Sections above that assume AGPL for the core (option a) are superseded. Binding criteria: MVP_CRITERIA.md r10 (3e601a1c…a8cb), L1 and A4. dahill checks the core graph with `cargo deny`.
