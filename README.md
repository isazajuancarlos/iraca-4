<!--
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
SPDX-License-Identifier: MIT
-->
# iraca-4 — arnés diferencial de ML-KEM (FIPS 203)

Cuarto de la familia **iraca** de verificación adversarial/diferencial de
criptografía post-cuántica (iraca-2 = ML-DSA, iraca-3 = SLH-DSA, **iraca-4 =
ML-KEM**).

A diferencia de iraca-2/3, que comparan dos crates de Rust entre sí, iraca-4
diferencia el crate `ml-kem`/`ml-dsa` que **quipu usa de verdad** (por `path` a su
copia vendorizada) contra **oráculos independientes**, en los **tres niveles** de
cada familia:

- **ML-KEM-512/768/1024** contra TRES oráculos: la **referencia C de pq-crystals**
  (kyber), **libcrux** (Cryspen/HACL*, Rust formalmente verificado) y **AWS-LC**
  (C de producción). Diferencial de **cuatro vías**.
- **ML-DSA-44/65/87** contra la **referencia C de pq-crystals** (dilithium), byte a
  byte. (AWS-LC no entra en firma: la suya es *hedged* y no expone la variante
  determinista `rnd=0` por la vía bindeada.)

Oráculos que no se conocen entre sí cierran el punto ciego que uno solo puede
compartir con el código medido: que quipu coincida con TODOS es una señal mucho
más fuerte que con uno.

## El método

Todas las implementaciones se alimentan con los **mismos bytes crudos** por sus
entradas deterministas — sin DRBG, sin vectores `.rsp`. Para ML-KEM-768:

| Etapa | pq-crystals C | libcrux | AWS-LC (`EVP_PKEY`) | quipu (`ml-kem`) |
|---|---|---|---|---|
| keygen | `..._keypair_derand(d‖z, 64 B)` | `generate_key_pair([u8;64])` | `EVP_PKEY_keygen_deterministic(seed 64 B)` | `DecapsulationKey::from_seed` |
| encaps | `..._enc_derand(pk, m, 32 B)` | `encapsulate(pk, [u8;32])` | `EVP_PKEY_encapsulate_deterministic(m 32 B)` | `encapsulate_deterministic(m)` |
| decaps | `..._dec(ct, sk)` | `decapsulate(sk, ct)` | `EVP_PKEY_decapsulate(ct)` | `decapsulate(ct)` |

Con determinismo de extremo a extremo, **cualquier discrepancia es real**, no ruido
de aleatoriedad. `build.rs` compila las referencias C con `cc` en sus tres niveles
(`KYBER_K=2/3/4`, `DILITHIUM_MODE=2/3/5`); el `fips202` (Keccak) K-independiente se
compila una vez por familia para no duplicar símbolos. El cableado por nivel se
genera con un `macro_rules!` (una sola expresión, instanciada por nivel) y la
comparación es genérica sobre una `Salida`/veredicto uniforme. libcrux y AWS-LC
entran de crates.io porque son **oráculos, no lo medido**; ninguno exige `libclang`
(AWS-LC compila con `cmake`+`cc`).

## Estado

Verde — todas las implementaciones **coinciden en todo**. Por nivel: acuerdo fijo,
128 semillas (D8), control positivo de que cada oráculo corrió (D30) y mutante que
pone rojo el banco por la vía real (D33).

- **ML-KEM-512/768/1024** — cuatro vías (quipu ↔ pq-crystals C ↔ libcrux ↔ AWS-LC),
  keygen + encaps + decaps byte a byte (`tests/niveles_kem.rs`).
- **ML-DSA-44/65/87** — quipu ↔ pq-crystals C: keygen (pk byte a byte) + firma
  determinista (sig byte a byte) + verificación cruzada + capa adversaria de
  canonicidad del hint (`tests/niveles_dsa.rs`). El keygen de dilithium no tiene
  `_derand`: `randombytes` lo provee Rust (`src/mldsa.rs`) con semilla por hilo; la
  firma va por `signature_internal` con `rnd=0`/`pre=[0,0]` = `Signer` de ml-dsa.
- Los bancos originales de ML-KEM-768 (dos/tres vías) y ML-DSA-87 de `lib.rs`/
  `src/mldsa.rs` siguen intactos (`tests/diferencial.rs`, `tres_oraculos.rs`,
  `mldsa.rs`).

48 pruebas verdes; clippy `-D warnings` limpio.

## Correr

```sh
cargo test    # requiere un compilador de C (cc) y cmake (para AWS-LC)
```
