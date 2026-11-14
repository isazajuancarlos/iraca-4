// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Banco diferencial de TRES vías para los TRES niveles de ML-KEM (512/768/1024):
//! el crate `ml-kem` de quipu contra la referencia C de pq-crystals y libcrux.
//! Cada nivel corre la misma pareja D33 (acuerdo real + mutante que DEBE discrepar
//! por la vía real), 128 semillas (D8) y control positivo de que la referencia C y
//! libcrux de verdad se ejecutaron (D30).

use iraca4::mlkem::{comparar, diferencia, Kem1024, Kem512, Kem768, NivelKem, Salida};

// PRNG determinista sin dependencias (splitmix64).
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

// --- Un cuerpo de pruebas genérico, instanciado por cada nivel abajo. ---

fn acuerdo_fijo<N: NivelKem>() {
    let coins = [7u8; 64];
    let m = [42u8; 32];
    let v = diferencia::<N>(&coins, &m);
    assert!(v.acuerdo_total(), "{}: las tres no concuerdan con entrada fija: {v:?}", N::NOMBRE);
}

fn control_positivo<N: NivelKem>() {
    // D30: los tres oráculos (C, libcrux, AWS-LC) tienen que haber corrido de
    // verdad. Sus pk NO triviales, deterministas, con el tamaño del nivel, y
    // coincidentes con la referencia C.
    let c = N::c(&[1u8; 64], &[0u8; 32]);
    let l = N::libcrux(&[1u8; 64], &[0u8; 32]);
    let a = N::aws(&[1u8; 64], &[0u8; 32]);
    assert_eq!(c.pk.len(), N::PK, "{}: tamaño pk C inesperado", N::NOMBRE);
    assert_eq!(l.pk.len(), N::PK, "{}: tamaño pk libcrux inesperado", N::NOMBRE);
    assert_eq!(a.pk.len(), N::PK, "{}: tamaño pk AWS-LC inesperado", N::NOMBRE);
    assert!(c.pk.iter().any(|&b| b != 0), "{}: pk C todo ceros (el .so no corrió)", N::NOMBRE);
    assert!(l.pk.iter().any(|&b| b != 0), "{}: pk libcrux todo ceros", N::NOMBRE);
    assert!(a.pk.iter().any(|&b| b != 0), "{}: pk AWS-LC todo ceros", N::NOMBRE);
    assert_eq!(c.pk, l.pk, "{}: C y libcrux divergen en pk con la misma semilla", N::NOMBRE);
    assert_eq!(c.pk, a.pk, "{}: C y AWS-LC divergen en pk con la misma semilla", N::NOMBRE);
    let a2 = N::aws(&[1u8; 64], &[0u8; 32]);
    assert_eq!(a.pk, a2.pk, "{}: AWS-LC no es determinista", N::NOMBRE);
    let c2 = N::c(&[1u8; 64], &[0u8; 32]);
    assert_eq!(c.pk, c2.pk, "{}: la referencia C no es determinista", N::NOMBRE);
}

fn mutante_discrimina<N: NivelKem>() {
    // D33 clavado por la vía real: alterar un byte de una salida por brazo debe
    // poner en falso el campo y acuerdo_total, a través de `comparar`.
    let coins = [7u8; 64];
    let m = [42u8; 32];
    let c = N::c(&coins, &m);
    let r = N::rust(&coins, &m);
    let l = N::libcrux(&coins, &m);
    let a = N::aws(&coins, &m);
    assert!(comparar(&c, &r, &l, &a).acuerdo_total(), "{}: base no concuerda", N::NOMBRE);

    let romper = |s: &Salida, campo: u8| -> Salida {
        let mut s = s.clone();
        match campo {
            0 => s.pk[0] ^= 0x01,
            1 => s.ct[0] ^= 0x01,
            2 => s.ss_enc[0] ^= 0x01,
            _ => s.ss_dec[0] ^= 0x01,
        }
        s
    };
    // Brazo libcrux, cada etapa.
    assert!(!comparar(&c, &r, &romper(&l, 0), &a).acuerdo_total(), "{}: libcrux/pk ciego", N::NOMBRE);
    assert!(!comparar(&c, &r, &romper(&l, 1), &a).acuerdo_total(), "{}: libcrux/ct ciego", N::NOMBRE);
    assert!(!comparar(&c, &r, &romper(&l, 2), &a).acuerdo_total(), "{}: libcrux/ss_enc ciego", N::NOMBRE);
    // Brazo AWS-LC, cada etapa.
    assert!(!comparar(&c, &r, &l, &romper(&a, 0)).acuerdo_total(), "{}: aws/pk ciego", N::NOMBRE);
    assert!(!comparar(&c, &r, &l, &romper(&a, 1)).acuerdo_total(), "{}: aws/ct ciego", N::NOMBRE);
    assert!(!comparar(&c, &r, &l, &romper(&a, 3)).acuerdo_total(), "{}: aws/ss_dec ciego", N::NOMBRE);
    // Brazo quipu.
    assert!(!comparar(&c, &romper(&r, 0), &l, &a).acuerdo_total(), "{}: quipu/pk ciego", N::NOMBRE);
    // Brazo C (referencia): alterarla rompe el acuerdo de las cuatro.
    assert!(!comparar(&romper(&c, 0), &r, &l, &a).acuerdo_total(), "{}: C/pk ciego", N::NOMBRE);
}

fn simula_128<N: NivelKem>() {
    let mut estado = 0x0123_4567_89AB_CDEFu64 ^ (N::PK as u64);
    let mut fallos = 0usize;
    for i in 0..128 {
        let mut coins = [0u8; 64];
        let mut m = [0u8; 32];
        llenar(&mut estado, &mut coins);
        llenar(&mut estado, &mut m);
        let v = diferencia::<N>(&coins, &m);
        if !v.acuerdo_total() {
            eprintln!("{} caso {i} discrepó: {v:?}", N::NOMBRE);
            fallos += 1;
        }
    }
    assert_eq!(fallos, 0, "{}: {fallos}/128 discreparon entre quipu, C, libcrux y AWS-LC", N::NOMBRE);
}

macro_rules! banco_nivel {
    ($modn:ident, $nivel:ty) => {
        mod $modn {
            use super::*;
            #[test]
            fn acuerdo_fijo_() { super::acuerdo_fijo::<$nivel>(); }
            #[test]
            fn control_positivo_() { super::control_positivo::<$nivel>(); }
            #[test]
            fn mutante_discrimina_() { super::mutante_discrimina::<$nivel>(); }
            #[test]
            fn simula_128_() { super::simula_128::<$nivel>(); }
        }
    };
}

banco_nivel!(kem512, Kem512);
banco_nivel!(kem768, Kem768);
banco_nivel!(kem1024, Kem1024);
