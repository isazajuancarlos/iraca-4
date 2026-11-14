<!--
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
SPDX-License-Identifier: MIT
-->
# Independent differential & adversarial verification of RustCrypto's ML-KEM against the pq-crystals reference

*Juan Carlos Isaza — Xiliux. 2026-09-25.*

## TL;DR

I build **iraca**, a family of cross-language harnesses that verify the
post-quantum crypto the Rust ecosystem actually ships — by differencing it against
an **independent** reference. This post reports a first result: the **RustCrypto
`ml-kem` (ML-KEM / FIPS 203)** crate — which is widely used but has **not** had a
published independent audit — is **byte-for-byte equivalent** to the pq-crystals C
reference across keygen / encapsulation / decapsulation, and **correctly enforces
the FIPS 203 encapsulation-key checks** (type check + modulus / non-canonicity
check). Method and exact scope below. The harness is reproducible.

This is a **conformance spot-check, not a full audit**, and it does **not** cover
timing / side-channel behavior (the KyberSlash class). What it offers is
independent, executable evidence for a few precisely-stated properties.

## Why this is worth doing

The NIST PQC standards (FIPS 203/204/205) are final, migration is mandated, and
much of the Rust world reaches for the RustCrypto `ml-kem` / `ml-dsa` crates — which
are, at the time of writing, **not independently audited**. In Rust PQC "the belt is
vacant": lots of implementations, little independent assurance. Differencing a
widely-used implementation against a separate one, in a *different language*, catches
the class of error that two ports could share.

## Method: same raw bytes to both sides

iraca feeds the **identical raw bytes** to the crate under test and to the
pq-crystals C reference, through their **deterministic entry points** — no DRBG, no
`.rsp` replay:

| Stage | pq-crystals C | RustCrypto crate |
|---|---|---|
| keygen | `crypto_kem_keypair_derand(coins = d‖z)` | `DecapsulationKey::from_seed(seed)` |
| encaps | `crypto_kem_enc_derand(pk, coins = m)` | `EncapsulationKey::encapsulate_deterministic(m)` |
| decaps | `crypto_kem_dec(ct, sk)` | `DecapsulationKey::decapsulate(ct)` |

With determinism end-to-end, **any disagreement is a real disagreement** between the
two implementations, not randomness noise. The C reference is compiled from source
via `cc` (KYBER_K=3, SHAKE only) and linked behind a thin FFI module; everything
else is safe Rust.

An **adversarial layer** then tests input-validation conformance: it generates
**non-canonical** encapsulation keys (a 12-bit coefficient ≥ q = 3329) and checks
whether the crate rejects them, as **FIPS 203 §7.2 requires** (the "modulus check":
`ByteEncode12(ByteDecode12(ek)) == ek`). The oracle for "is this key canonical?" is
the **standard itself** (computed independently in the harness), not another
implementation — so the needle is validated against the artifact (the FIPS text),
with paired valid/invalid cases and a positive control that the reject path actually
executes.

## Results (scoped)

- **Functional differential — ML-KEM-768**: keygen + encaps + decaps produce
  **byte-identical** public keys, ciphertexts and shared secrets to the pq-crystals
  reference across **128 pseudo-random seeds** plus a fixed vector.
- **Adversarial conformance — ML-KEM-768**: RustCrypto `ml-kem` **rejects
  non-canonical encapsulation keys** (FIPS 203 encapsulation-key check). Confirmed
  both by reading the source (the check is implemented and cites FIPS 203 verbatim)
  **and** by execution over 128 samples: every valid key accepted, every
  non-canonical mutant rejected.
- **Companion result — ML-DSA-87**: the same cross-language differential shows
  RustCrypto `ml-dsa` keygen, deterministic signing and verification agree
  byte-for-byte with the dilithium reference (128 seeds), with cross-verification
  (each side accepts the other's signature) and a tamper test (a flipped byte is
  rejected by both).

Every result carries a red/green pair and a positive control, so a "no disagreement"
means the comparison path actually ran and can discriminate — not that it looked at
nothing.

## What this is NOT

- Not a full security audit; it checks specific, stated properties.
- Not timing / side-channel analysis (KyberSlash-class issues need measurement, not
  I/O differencing; the well-known ones are already patched).
- One crate version, three properties. Assurance is cumulative, not a single stamp.

## Reproducibility & collaboration

The harness (iraca-4) is small, deterministic, and built to be re-run. If you
maintain a PQC implementation and want an independent differential/adversarial pass
— or an oracle to diff your own work against — this is exactly what it's for. I also
work with the Ethereum Foundation's post-quantum effort on signature-scheme
verification.

Contact: through the Xiliux contact form.
