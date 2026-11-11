# iraca-4

Cross-language differential harness for ML-KEM (FIPS 203) and ML-DSA (FIPS 204):
byte-by-byte agreement across Rust, formally verified C, and production C, at all
parameter levels. MIT.  
FIPS 203 · FIPS 204 · ML-KEM · ML-DSA · cross-language differential · pq-crystals · libcrux · AWS-LC

**English** · [Español](#español)

---

## The code is not hosted here

Since August 2026 the source of this project **is not hosted on GitHub**, and it
is not distributed through crates.io or any public registry.

This is not abandonment, not an incident, and there was no breach. It is a
decision, and it is worth saying what it rests on. Through 2026 the package
registries and code-hosting platforms were hit by sustained, chained
supply-chain attacks — the Shai-Hulud worm, ChainDrop in August, malicious
extensions that exfiltrated thousands of private repositories. For a
cryptographic verification tool, hosting the source there stopped being a
neutral decision.

**The licence has not changed and the code is still available to anyone who
asks** — delivered with a signature and a checksum, at no cost, with no NDA, no
restriction on what you publish about it, and no expiry.

### Get the source

Request the signed source via **[xiliux.com](https://xiliux.com)**.

---

## What it does

Unlike the other iraca tools — which compare two Rust crates against each other —
iraca-4 **crosses the language boundary**: the Rust implementation under test is
verified against independent C oracles at every step, byte by byte. Oracles that
share no code with each other and none with the Rust implementation close the
blind spot that any single oracle may share with the code it measures.

All implementations are fed the **same raw bytes** via deterministic entry points
(no DRBG, no `.rsp` vectors). With end-to-end determinism, **any discrepancy is
real**, not randomness noise.

### ML-KEM — four-way differential (all three parameter levels)

Subjects: `ml-kem` (Rust) · pq-crystals **kyber** reference C · **libcrux**
(Cryspen/HACL*, formally verified, Rust) · **AWS-LC** (AWS production C).

Stages covered byte-by-byte at ML-KEM-512, ML-KEM-768, and ML-KEM-1024:
key generation (`keygen_derand`) · encapsulation (`enc_derand`) · decapsulation.

### ML-DSA — Rust ↔ pq-crystals C (all three parameter levels)

Subjects: `ml-dsa` (Rust) · pq-crystals **dilithium** reference C.

ML-DSA-44, ML-DSA-65, and ML-DSA-87: public key byte-by-byte · deterministic
signature byte-by-byte · cross-verification · structural hint canonicity (the
same abuse surface as iraca-2 phase 3).

### Result

**48 green tests. All implementations agree on every entry across all parameter
levels.**

Each level carries a positive control (proving the oracle ran) and a mutant
(one corrupted byte forces the harness red via the real oracle path), so the
"all green" result is not vacuous.

---

## Español

**[English](#iraca-4)** · Español

Arnés diferencial entre lenguajes para ML-KEM (FIPS 203) y ML-DSA (FIPS 204):
acuerdo byte-a-byte entre Rust, C formalmente verificado y C de producción, en
todos los niveles de parámetros. MIT.  
FIPS 203 · FIPS 204 · ML-KEM · ML-DSA · diferencial entre lenguajes · pq-crystals · libcrux · AWS-LC

---

### El código no se publica aquí

Desde agosto de 2026, el código de este proyecto **no se aloja en GitHub**, ni
se distribuye por crates.io ni ningún registro público.

No es abandono ni un incidente: es una decisión. A lo largo de 2026 los
registros de paquetes y las plataformas de código han sufrido ataques
encadenados de cadena de suministro —Shai-Hulud, ChainDrop en agosto,
extensiones maliciosas que se llevaron miles de repositorios privados—. Alojar
aquí el código de una herramienta de verificación criptográfica dejó de ser una
decisión neutra.

**La licencia no cambia y el código se sigue entregando a quien lo pida**, con
su firma y su suma de verificación, sin coste, sin NDA, sin restricción sobre lo
que publique y sin caducidad.

### Conseguir el código

Solicite el fuente firmado en **[xiliux.com](https://xiliux.com)**.

---

### Qué hace

A diferencia de los otros arneses de la familia iraca —que comparan dos crates
de Rust entre sí—, iraca-4 **cruza la frontera del lenguaje**: la implementación
Rust bajo prueba se verifica contra oráculos C independientes, paso a paso, byte
a byte. Oráculos que no comparten código entre sí ni con la implementación Rust
cierran el punto ciego que cualquier oráculo individual puede compartir con el
código que mide.

Todas las implementaciones reciben los **mismos bytes crudos** por sus entradas
deterministas. Con determinismo de extremo a extremo, **cualquier discrepancia
es real**, no ruido de aleatoriedad.

### ML-KEM — diferencial de cuatro vías (los tres niveles de parámetros)

Sujetos: `ml-kem` (Rust) · referencia C **kyber** de pq-crystals · **libcrux**
(Cryspen/HACL*, formalmente verificado, Rust) · **AWS-LC** (C de producción de AWS).

Etapas cubiertas byte a byte en ML-KEM-512, ML-KEM-768 y ML-KEM-1024:
generación de clave · encapsulación · desencapsulación.

### ML-DSA — Rust ↔ pq-crystals C (los tres niveles de parámetros)

Sujetos: `ml-dsa` (Rust) · referencia C **dilithium** de pq-crystals.

ML-DSA-44, ML-DSA-65 y ML-DSA-87: clave pública byte a byte · firma determinista
byte a byte · verificación cruzada · canonicidad estructural del hint (misma
superficie de abuso que iraca-2 fase 3).

### Resultado

**48 pruebas verdes. Todas las implementaciones acuerdan en cada entrada y en
todos los niveles de parámetros.**

Cada nivel lleva un control positivo (que prueba que el oráculo corrió) y un
mutante (un byte corrompido fuerza el arnés al rojo por la vía real del oráculo),
de modo que el «todo verde» no es vacuo.

---

*iraca-4* — © 2026 Juan Carlos Isaza. Licence: **MIT**.  
La licencia no cambia: lo que cambia es cómo se entrega el código.
