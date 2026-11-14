// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Banco diferencial de los TRES niveles de ML-DSA (44/65/87): el crate `ml-dsa`
//! de quipu contra la referencia C de pq-crystals (dilithium), byte a byte, con
//! verificación cruzada. Por nivel: acuerdo fijo, control positivo D30, mutante
//! D33 (firma alterada que ambos rechazan) y 128 semillas D8. Además, la pasada
//! ADVERSARIA de canonicidad del hint (no-canónico → ambos deben rechazar).

use iraca4::mldsa_niveles::{
    adversario_hint, diferencia, mutar_hint_no_canonico, Dsa44, Dsa65, Dsa87, NivelDsa,
};

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

fn acuerdo_fijo<N: NivelDsa>() {
    let seed = [7u8; 32];
    let m = b"iraca-4 :: mensaje de prueba fijo";
    let v = diferencia::<N>(&seed, m);
    assert!(v.acuerdo_total(), "{}: quipu y C no concuerdan con entrada fija: {v:?}", N::NOMBRE);
}

fn control_positivo<N: NivelDsa>() {
    // D30: la referencia C corrió de verdad — pk NO trivial, del tamaño del nivel,
    // determinista, y se verifica a sí misma.
    let (pk_c, sk_c) = N::c_keypair(&[1u8; 32]);
    assert_eq!(pk_c.len(), N::PK, "{}: tamaño pk C inesperado", N::NOMBRE);
    assert!(pk_c.iter().any(|&b| b != 0), "{}: pk C todo ceros (el .so no corrió)", N::NOMBRE);
    let (pk_c2, _) = N::c_keypair(&[1u8; 32]);
    assert_eq!(pk_c, pk_c2, "{}: la referencia C no es determinista", N::NOMBRE);
    let sig = N::c_sign(&sk_c, b"x");
    assert_eq!(sig.len(), N::SIG, "{}: tamaño de firma C inesperado", N::NOMBRE);
    assert!(N::c_verify(&pk_c, b"x", &sig), "{}: la firma C no verifica en C", N::NOMBRE);
}

fn mutante_firma_alterada<N: NivelDsa>() {
    // D33 por la vía real: una firma con un byte cambiado NO debe verificar en
    // ninguno de los dos; y semillas distintas deben dar pk distinta.
    let seed = [9u8; 32];
    let m = b"mensaje";
    let (pk_c, sk_c) = N::c_keypair(&seed);
    let sig = N::c_sign(&sk_c, m);
    assert!(N::c_verify(&pk_c, m, &sig) && N::rust_verify(&pk_c, m, &sig), "{}: base no verifica", N::NOMBRE);

    let mut mala = sig;
    mala[0] ^= 0x01;
    assert!(!N::c_verify(&pk_c, m, &mala), "{}: C aceptó firma alterada", N::NOMBRE);
    assert!(!N::rust_verify(&pk_c, m, &mala), "{}: quipu aceptó firma alterada", N::NOMBRE);

    let (pk_b, _) = N::c_keypair(&[10u8; 32]);
    assert_ne!(pk_c, pk_b, "{}: semillas distintas dieron la misma pk (comparación ciega)", N::NOMBRE);
}

fn simula_128<N: NivelDsa>() {
    let mut estado = 0xF00D_BA5E_1234_5678u64 ^ (N::SIG as u64);
    let m = b"barrido de 128 semillas";
    let mut fallos = 0usize;
    for i in 0..128 {
        let mut seed = [0u8; 32];
        llenar(&mut estado, &mut seed);
        let v = diferencia::<N>(&seed, m);
        if !v.acuerdo_total() {
            eprintln!("{} caso {i} discrepó: {v:?}", N::NOMBRE);
            fallos += 1;
        }
    }
    assert_eq!(fallos, 0, "{}: {fallos}/128 discreparon entre quipu y C", N::NOMBRE);
}

fn adversario_hint_limpio<N: NivelDsa>() {
    // La firma no-canónica (relleno de hint != 0) DEBE ser rechazada por ambos.
    // El control positivo va dentro (la válida verifica en los dos); si el ataque
    // no encuentra hueco en ninguna, se salta y se dice.
    let mut estado = 0xABCD_1234_5678_9AB0u64 ^ (N::OMEGA as u64);
    let mut semillas = Vec::new();
    for _ in 0..64 {
        let mut s = [0u8; 32];
        llenar(&mut estado, &mut s);
        semillas.push(s);
    }
    let r = adversario_hint::<N>(&semillas, b"adversario hint");
    // D30: el negativo ("ambos rechazan") solo vale si el camino se ejecutó. Sin
    // esto, cero firmas con hueco daría limpio() == true en vacío.
    assert!(r.probadas > 0, "{}: ninguna firma tenía hueco de hint que ensuciar (control D30): {r:?}", N::NOMBRE);
    assert!(r.limpio(), "{}: hueco de canonicidad del hint: {r:?}", N::NOMBRE);
    // Positivo fuerte: AMBOS lados rechazaron TODAS las no-canónicas probadas
    // (no solo "no hubo desacuerdo"), que es lo que FIPS 204 exige.
    assert_eq!(r.c_rechaza, r.probadas, "{}: C no rechazó todas las no-canónicas: {r:?}", N::NOMBRE);
    assert_eq!(r.rust_rechaza, r.probadas, "{}: quipu no rechazó todas las no-canónicas: {r:?}", N::NOMBRE);

    // Discriminación (D33): la mutación produce un buffer DISTINTO y rechazable.
    let (pk, sk) = N::c_keypair(&[3u8; 32]);
    let sig = N::c_sign(&sk, b"adversario hint");
    let mut_sig = mutar_hint_no_canonico::<N>(&sig)
        .unwrap_or_else(|| panic!("{}: la firma fija no tenía hueco de hint (control D30)", N::NOMBRE));
    assert_ne!(mut_sig, sig, "{}: la mutación no cambió la firma", N::NOMBRE);
    assert!(!N::c_verify(&pk, b"adversario hint", &mut_sig), "{}: C aceptó hint no-canónico", N::NOMBRE);
}

macro_rules! banco_dsa {
    ($modn:ident, $nivel:ty) => {
        mod $modn {
            use super::*;
            #[test]
            fn acuerdo_fijo_() { super::acuerdo_fijo::<$nivel>(); }
            #[test]
            fn control_positivo_() { super::control_positivo::<$nivel>(); }
            #[test]
            fn mutante_firma_alterada_() { super::mutante_firma_alterada::<$nivel>(); }
            #[test]
            fn simula_128_() { super::simula_128::<$nivel>(); }
            #[test]
            fn adversario_hint_() { super::adversario_hint_limpio::<$nivel>(); }
        }
    };
}

banco_dsa!(dsa44, Dsa44);
banco_dsa!(dsa65, Dsa65);
banco_dsa!(dsa87, Dsa87);
