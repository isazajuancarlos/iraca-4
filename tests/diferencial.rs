// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Banco diferencial ML-KEM-768: crate de quipu ↔ referencia C de pq-crystals.
//! Pareja D33 (acuerdo real + mutante que DEBE discrepar), 128 corridas (D8) y
//! control positivo de que la referencia C de verdad se ejecutó (D30).

use iraca4::{c_keypair, diferencia, rust_roundtrip, CT, PK, SS};

// PRNG determinista sin dependencias (splitmix64), para barrer semillas.
fn sm64(estado: &mut u64) -> u64 {
    *estado = estado.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *estado;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn llenar(estado: &mut u64, buf: &mut [u8]) {
    for trozo in buf.chunks_mut(8) {
        let v = sm64(estado).to_le_bytes();
        trozo.copy_from_slice(&v[..trozo.len()]);
    }
}

#[test]
fn acuerdo_en_semilla_fija() {
    // Semilla y m fijos y conocidos: C y Rust deben coincidir en TODAS las etapas
    // (ek, ct, ss al encapsular y al decapsular) y cerrar el round-trip cada uno.
    let coins = [7u8; 64];
    let m = [42u8; 32];
    let v = diferencia(&coins, &m);
    assert!(v.acuerdo_total(), "discrepancia C↔Rust con entrada fija: {v:?}");
}

#[test]
fn control_positivo_la_referencia_c_corrio() {
    // D30: un "acuerdo" solo vale si el camino que lo produce se ejecutó. La
    // referencia C tiene que devolver una pk NO trivial (no todo ceros).
    let (pk_c, _sk_c) = c_keypair(&[1u8; 64]);
    assert_eq!(pk_c.len(), PK);
    assert!(pk_c.iter().any(|&b| b != 0), "la pk de C es todo ceros: el .so no corrió");
    // Y dos corridas con la misma semilla dan la misma pk (determinismo real).
    let (pk_c2, _) = c_keypair(&[1u8; 64]);
    assert_eq!(pk_c, pk_c2, "la referencia C no es determinista con semilla fija");
}

#[test]
fn mutante_semillas_distintas_deben_discrepar() {
    // D33: el caso rojo por la vía real. Si comparo la pk de C generada con la
    // semilla A contra la ek de Rust generada con la semilla B, DEBEN diferir; si
    // no, la comparación de bytes es ciega y el verde de arriba no vale nada.
    let (pk_c, _) = c_keypair(&[1u8; 64]);
    let r = rust_roundtrip(&[2u8; 64], &[0u8; 32]);
    assert_ne!(r.ek, pk_c, "semillas distintas produjeron la misma ek: comparación ciega");
}

#[test]
fn mutante_m_distinto_cambia_el_ct() {
    // Segunda aguja de discriminación: mismo par de claves, m distinto → el ct
    // debe cambiar (prueba que la comparación de ct no es trivial).
    let coins = [9u8; 64];
    let a = rust_roundtrip(&coins, &[1u8; 32]);
    let b = rust_roundtrip(&coins, &[2u8; 32]);
    assert_eq!(a.ek, b.ek, "misma semilla debería dar la misma ek");
    assert_ne!(a.ct, b.ct, "m distinto debería cambiar el ct");
    assert_eq!(a.ct.len(), CT);
}

#[test]
fn simula_128_semillas() {
    // D8: 128 (semilla, m) pseudo-aleatorios; acuerdo total en cada uno.
    let mut estado = 0xDEAD_BEEF_CAFE_F00Du64;
    let mut fallos = 0usize;
    for i in 0..128 {
        let mut coins = [0u8; 64];
        let mut m = [0u8; 32];
        llenar(&mut estado, &mut coins);
        llenar(&mut estado, &mut m);
        let v = diferencia(&coins, &m);
        if !v.acuerdo_total() {
            eprintln!("caso {i} discrepó: {v:?}");
            fallos += 1;
        }
    }
    assert_eq!(fallos, 0, "{fallos}/128 casos discreparon entre quipu y la referencia C");
}

#[test]
fn tamano_de_clave_compartida() {
    let r = rust_roundtrip(&[3u8; 64], &[4u8; 32]);
    assert_eq!(r.ss_enc.len(), SS);
    assert_eq!(r.ss_enc, r.ss_dec, "el round-trip de Rust no cerró");
}
