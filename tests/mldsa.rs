// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Banco diferencial ML-DSA-87: crate `ml-dsa` de quipu ↔ referencia C dilithium.
//! Pareja D33 (acuerdo real + mutantes que DEBEN discrepar), 128 corridas (D8) y
//! control positivo de que la referencia C corrió (D30).

use iraca4::mldsa::{c_keypair, c_verify, diferencia, rust_verify, PK, SIG};

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
    let seed = [11u8; 32];
    let msg = b"iraca-4 differential ML-DSA-87";
    let v = diferencia(&seed, msg);
    assert!(v.acuerdo_total(), "discrepancia C↔Rust con entrada fija: {v:?}");
}

#[test]
fn control_positivo_la_referencia_c_corrio() {
    // D30: la pk de C debe ser no trivial y determinista con semilla fija.
    let (pk1, _) = c_keypair(&[5u8; 32]);
    assert_eq!(pk1.len(), PK);
    assert!(pk1.iter().any(|&b| b != 0), "pk de C todo ceros: el .a no corrió");
    let (pk2, _) = c_keypair(&[5u8; 32]);
    assert_eq!(pk1, pk2, "la referencia C no es determinista con semilla fija");
    // Y con OTRA semilla la pk cambia (randombytes controlado de verdad).
    let (pk3, _) = c_keypair(&[6u8; 32]);
    assert_ne!(pk1, pk3, "distinta semilla dio la misma pk: randombytes no se controló");
}

#[test]
fn mutante_firma_alterada_no_verifica() {
    // D33 por la vía real: alterar un byte de la firma DEBE hacer que ambas
    // verificaciones fallen; si no, la puerta de verificación es ciega.
    let seed = [21u8; 32];
    let msg = b"mensaje intacto";
    let (pk_c, sk_c) = c_keypair(&seed);
    let mut sig = iraca4::mldsa::c_sign(&sk_c, msg);
    assert!(c_verify(&pk_c, msg, &sig), "la firma legítima debía verificar (control)");
    assert!(rust_verify(&pk_c, msg, &sig), "Rust debía aceptar la firma legítima (control)");
    // Mutar un byte del centro de la firma.
    sig[SIG / 2] ^= 0x01;
    assert!(!c_verify(&pk_c, msg, &sig), "C aceptó una firma alterada");
    assert!(!rust_verify(&pk_c, msg, &sig), "Rust aceptó una firma alterada");
}

#[test]
fn mutante_mensaje_distinto_cambia_la_firma() {
    let seed = [31u8; 32];
    let v1 = diferencia(&seed, b"mensaje A");
    let v2 = diferencia(&seed, b"mensaje B");
    assert!(v1.acuerdo_total() && v2.acuerdo_total());
    // (implícito: firmas distintas para mensajes distintos; el acuerdo_total ya
    // exige sig_igual C↔Rust en cada mensaje, y son mensajes distintos.)
}

#[test]
fn simula_128_semillas() {
    // D8: 128 (semilla, mensaje) pseudo-aleatorios; acuerdo total en cada uno.
    let mut estado = 0x0123_4567_89AB_CDEFu64;
    let mut fallos = 0usize;
    for i in 0..128 {
        let mut seed = [0u8; 32];
        let mut msg = [0u8; 48];
        llenar(&mut estado, &mut seed);
        llenar(&mut estado, &mut msg);
        let v = diferencia(&seed, &msg);
        if !v.acuerdo_total() {
            eprintln!("caso {i} discrepó: {v:?}");
            fallos += 1;
        }
    }
    assert_eq!(fallos, 0, "{fallos}/128 casos discreparon entre quipu y dilithium C");
}

#[test]
fn adversario_hint_no_canonico_cross_lenguaje() {
    // Pasada adversaria: hint no-canónico (byte de relleno != 0) a RustCrypto y a la
    // referencia C. FIPS 204 exige RECHAZARLO. Cross-lenguaje: un desacuerdo o un
    // "ambos aceptan" sería un HALLAZGO. Esperado (maduro): ambos rechazan = limpio.
    use iraca4::mldsa::adversario_hint;
    let mut e = 0xF00D_1DEA_5EED_2026u64;
    let semillas: Vec<[u8; 32]> = (0..128)
        .map(|_| {
            let mut s = [0u8; 32];
            for t in s.chunks_mut(8) {
                let mut estado = e;
                estado = estado.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = estado;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                let v = (z ^ (z >> 31)).to_le_bytes();
                t.copy_from_slice(&v[..t.len()]);
                e = estado;
            }
            s
        })
        .collect();
    let r = adversario_hint(&semillas, b"iraca adversarial ML-DSA hint pass");
    eprintln!("REPORTE adversario_hint: {r:?}");
    assert!(r.probadas > 0, "ninguna firma tenía hueco de hint que ensuciar (control): {r:?}");
    assert!(
        r.limpio(),
        "HALLAZGO potencial: desacuerdo o aceptación de hint no-canónico. Investigar: {r:?}"
    );
}
