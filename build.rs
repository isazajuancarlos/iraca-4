// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Compila las referencias C de pq-crystals como librerías estáticas, en los TRES
//! niveles de cada familia:
//!   - kyber     → ML-KEM-512/768/1024  (KYBER_K = 2/3/4)
//!   - dilithium → ML-DSA-44/65/87      (DILITHIUM_MODE = 2/3/5)
//!
//! Ninguna compila su `randombytes.c`: `randombytes` lo provee UNA vez el crate
//! (`src/mldsa.rs`, símbolo `#[no_mangle]`), controlado desde Rust para el keygen
//! de dilithium. kyber nunca lo llama (solo usamos sus variantes `_derand`), pero
//! el símbolo tiene que resolver igual — de ahí la definición única en Rust.
//! Sin OpenSSL: el DRBG AES-CTR del NIST-KAT no se compila (no lo usamos).
//!
//! **La trampa de enlace con varios niveles, y cómo se evita:** casi todos los
//! fuentes están namespaceados por nivel (`KYBER_NAMESPACE`/`DILITHIUM_NAMESPACE`),
//! así que compilarlos una vez por nivel produce símbolos DISTINTOS y se pueden
//! enlazar juntos. La excepción es `fips202.c` (Keccak), cuyo namespace
//! (`pqcrystals_kyber_fips202_ref_*` / `pqcrystals_dilithium_fips202_ref_*`) NO
//! depende del nivel: compilarlo por nivel duplicaría símbolos → error de enlace.
//! Por eso `fips202.c` se compila UNA sola vez por familia, y **al final**, para
//! que satisfaga las referencias no resueltas de las libs de nivel (el enlazador
//! procesa de izquierda a derecha, así que el proveedor de un símbolo debe venir
//! DESPUÉS de quien lo usa). Los `fips202` de kyber y dilithium no colisionan
//! entre sí (namespaces distintos).

fn main() {
    // --- kyber (ML-KEM), fuentes namespaceadas por KYBER_K ---
    let ky = "vendor/kyber-ref";
    let ky_nivel = [
        "kem.c", "indcpa.c", "polyvec.c", "poly.c", "ntt.c", "cbd.c", "reduce.c",
        "verify.c", "symmetric-shake.c",
    ];
    for (k, nombre) in [("2", "kyber512ref"), ("3", "kyber768ref"), ("4", "kyber1024ref")] {
        let mut b = cc::Build::new();
        b.include(ky);
        for f in &ky_nivel {
            b.file(format!("{ky}/{f}"));
        }
        b.define("KYBER_K", k);
        b.warnings(false);
        b.compile(nombre);
    }

    // --- dilithium (ML-DSA), fuentes namespaceadas por DILITHIUM_MODE ---
    let di = "vendor/dilithium-ref";
    let di_nivel = [
        "sign.c", "packing.c", "polyvec.c", "poly.c", "ntt.c", "reduce.c",
        "rounding.c", "symmetric-shake.c",
    ];
    for (mode, nombre) in [("2", "dilithium2ref"), ("3", "dilithium3ref"), ("5", "dilithium5ref")] {
        let mut d = cc::Build::new();
        d.include(di);
        for f in &di_nivel {
            d.file(format!("{di}/{f}"));
        }
        d.define("DILITHIUM_MODE", mode);
        d.warnings(false);
        d.compile(nombre);
    }

    // --- Keccak/fips202 K-independiente: UNA vez por familia, al FINAL ---
    {
        let mut b = cc::Build::new();
        b.include(ky);
        b.file(format!("{ky}/fips202.c"));
        b.warnings(false);
        b.compile("kyber_fips202");
    }
    {
        let mut d = cc::Build::new();
        d.include(di);
        d.file(format!("{di}/fips202.c"));
        d.warnings(false);
        d.compile("dilithium_fips202");
    }

    println!("cargo:rerun-if-changed={ky}");
    println!("cargo:rerun-if-changed={di}");
}
