<!-- Texto TURNKEY para que Juan lo publique — NO lo envía Claude (requiere la
cuenta de GitHub de Juan y es irreversible). Destino sugerido: una GitHub
Discussion (categoría "Show and tell" o "General") en el repo RustCrypto
(github.com/RustCrypto/KEMs para ml-kem). NO abrir un "issue" salvo que sea un bug:
esto es una contribución/aporte, no un reporte de fallo. -->

# Título sugerido
Independent differential & adversarial verification of `ml-kem` vs the pq-crystals reference (FIPS 203)

# Cuerpo (pegar tal cual)

Hi RustCrypto team,

I've been building small **cross-language differential harnesses** for the NIST PQC
implementations, and I ran one against `ml-kem`. Sharing the results here since the
crate is widely used and, as far as I can tell, hasn't had a published independent
audit — this isn't an audit either, just independent, reproducible evidence for a
few concrete properties.

**Method (no DRBG, no KAT replay):** I feed the *same raw bytes* to `ml-kem` and to
the pq-crystals C reference through their deterministic entry points
(`from_seed` / `encapsulate_deterministic` on your side; `crypto_kem_*_derand` on
theirs), so any disagreement is real rather than randomness noise. An adversarial
layer then generates **non-canonical encapsulation keys** (a 12-bit coefficient
≥ q) and checks they're rejected, with the FIPS 203 canonicity rule computed
independently as the oracle. Every check ships a red/green pair and a positive
control.

**Results for ML-KEM-768 (`ml-kem` 0.3):**
- keygen / encaps / decaps are **byte-for-byte identical** to pq-crystals across 128
  seeds + a fixed vector;
- the crate **correctly rejects non-canonical encapsulation keys** (FIPS 203 §7.2
  encapsulation-key check) — I see it implemented in `pke.rs` and confirmed it by
  execution over 128 samples.

So: a clean assurance result, nothing to fix here. I'm posting it as a data point
and to offer the harness — if it'd be useful as an independent oracle in CI, or if
you'd like me to run the same differential/adversarial pass against `ml-dsa` /
`slh-dsa`, happy to help.

Write-up with the method and scope:
https://xiliux.com/en/blog/verificacion-diferencial-ml-kem-rustcrypto

Thanks for the crates.

— Juan Carlos Isaza (Xiliux)

# Notas para Juan
- Es un APORTE, no un bug → Discussion, no Issue. Tono humilde, sin sobre-afirmar.
- Si prefieres pqc-forum (lista NIST), NO pegues esto tal cual: esa lista es para
  estándares; solo aportaría si hay algo forum-worthy (p. ej. un hallazgo real en
  ML-DSA). Para promoción del método, GitHub Discussion es mejor primer paso.
- El enlace ya está vivo (verificado). Revisa el writeup antes de postear por si
  quieres ajustar el tono a tu voz.
