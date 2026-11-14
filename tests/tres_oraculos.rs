// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Banco diferencial de TRES vías para ML-KEM-768: el crate `ml-kem` que quipu
//! usa, contra sus DOS oráculos independientes — la referencia C de pq-crystals
//! y libcrux (Cryspen/HACL*, Rust formalmente verificado).
//!
//! Dos oráculos que no se conocen entre sí cierran el punto ciego que un solo
//! oráculo puede compartir con el código medido (D33,
//! [[nexus-firma-no-verificada-punto-ciego-del-control]]). Pareja D33 (acuerdo
//! real + mutante que DEBE discrepar por la vía real), 128 corridas (D8) y
//! control positivo de que libcrux de verdad se ejecutó (D30).

use iraca4::{
    c_enc, c_dec, c_keypair, comparar_tres, diferencia_tres, libcrux_roundtrip, rust_roundtrip,
    LibcruxOut, RustOut, CT, PK, SS,
};

// PRNG determinista sin dependencias (splitmix64), idéntico al de diferencial.rs.
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
fn acuerdo_tres_en_semilla_fija() {
    // Semilla y m fijos: quipu, la referencia C y libcrux deben coincidir en
    // TODAS las etapas (pk/ek, ct, ss al encapsular y al decapsular) y cerrar el
    // round-trip cada una.
    let coins = [7u8; 64];
    let m = [42u8; 32];
    let v = diferencia_tres(&coins, &m);
    assert!(
        v.acuerdo_total(),
        "las tres implementaciones no concuerdan con entrada fija: {v:?}"
    );
}

#[test]
fn control_positivo_libcrux_corrio() {
    // D30: un "acuerdo" solo vale si el camino que lo produce se ejecutó.
    // libcrux tiene que devolver una pk NO trivial (no todo ceros)...
    let l = libcrux_roundtrip(&[1u8; 64], &[0u8; 32]);
    assert_eq!(l.pk.len(), PK);
    assert!(
        l.pk.iter().any(|&b| b != 0),
        "la pk de libcrux es todo ceros: la implementación no corrió"
    );
    // ...y ser determinista con semilla fija (dos corridas, la misma pk)...
    let l2 = libcrux_roundtrip(&[1u8; 64], &[0u8; 32]);
    assert_eq!(l.pk, l2.pk, "libcrux no es determinista con semilla fija");
    // ...y su round-trip tiene que cerrar (ss_enc == ss_dec).
    assert_eq!(l.ss_enc, l.ss_dec, "el round-trip de libcrux no cerró");
    assert_eq!(l.ss_enc.len(), SS);
    // Positivo de control fuerte: con la misma semilla, libcrux coincide con la
    // referencia C — prueba que no es un stub que devuelve datos plausibles pero
    // ajenos al estándar.
    let (pk_c, _sk_c) = c_keypair(&[1u8; 64]);
    assert_eq!(
        l.pk,
        pk_c,
        "libcrux y la referencia C divergen en la pk con la misma semilla"
    );
}

#[test]
fn mutante_libcrux_semilla_distinta_discrepa() {
    // D33, la vía real: la comparación de bytes contra libcrux no puede ser ciega.
    // Si comparo la pk que libcrux genera con la semilla A contra la pk que C
    // genera con la semilla B, DEBEN diferir; si coincidieran, un verde de
    // acuerdo no valdría nada.
    let l = libcrux_roundtrip(&[1u8; 64], &[0u8; 32]);
    let (pk_c_b, _) = c_keypair(&[2u8; 64]);
    assert_ne!(
        l.pk, pk_c_b,
        "semillas distintas produjeron la misma pk: comparación ciega"
    );

    // Segunda aguja: un bit alterado en la semilla de libcrux cambia su pk, así
    // que una divergencia REAL de libcrux la cazaría diferencia_tres.
    let base = libcrux_roundtrip(&[1u8; 64], &[0u8; 32]);
    let mut coins = [1u8; 64];
    coins[0] ^= 0x01; // un solo bit
    let alterada = libcrux_roundtrip(&coins, &[0u8; 32]);
    assert_ne!(
        base.pk, alterada.pk,
        "un bit alterado en la semilla no cambió la pk de libcrux"
    );

    // Tercera aguja: mismo par de claves, m distinto → el ct debe cambiar.
    let a = libcrux_roundtrip(&[9u8; 64], &[1u8; 32]);
    let b = libcrux_roundtrip(&[9u8; 64], &[2u8; 32]);
    assert_eq!(a.pk, b.pk, "misma semilla debería dar la misma pk");
    assert_ne!(a.ct, b.ct, "m distinto debería cambiar el ct");
    assert_eq!(a.ct.len(), CT);
}

#[test]
fn cruce_libcrux_vs_quipu_directo() {
    // Refuerzo del cruce que importa: libcrux (oráculo verificado) contra el
    // ml-kem que quipu usa de verdad, sin pasar por C. Si estos dos difieren, el
    // sospechoso es quipu (libcrux está formalmente verificado).
    let coins = [55u8; 64];
    let m = [66u8; 32];
    let q = rust_roundtrip(&coins, &m);
    let l = libcrux_roundtrip(&coins, &m);
    assert_eq!(q.ek.as_slice(), l.pk.as_slice(), "quipu y libcrux difieren en la ek");
    assert_eq!(q.ct.as_slice(), l.ct.as_slice(), "quipu y libcrux difieren en el ct");
    assert_eq!(q.ss_enc, l.ss_enc, "quipu y libcrux difieren en ss_enc");
    assert_eq!(q.ss_dec, l.ss_dec, "quipu y libcrux difieren en ss_dec");
}

#[test]
fn comparar_tres_discrimina_cada_brazo() {
    // D33 clavado en el repo (antes solo lo probaba un mutante corrido a mano):
    // que CADA brazo de comparar_tres se compare de verdad, que ningún `&& x == y`
    // esté muerto a `&& true`. Partimos de una corrida real donde las tres
    // concuerdan y, alterando un byte de una salida a la vez, exigimos que el
    // campo correspondiente —y acuerdo_total— se ponga en falso por la vía real.
    let coins = [7u8; 64];
    let m = [42u8; 32];
    let (pk_c, sk_c) = c_keypair(&coins);
    let (ct_c, ss_enc_c) = c_enc(&pk_c, &m);
    let ss_dec_c = c_dec(&ct_c, &sk_c);
    let r = rust_roundtrip(&coins, &m);
    let l = libcrux_roundtrip(&coins, &m);

    // Línea base: las tres concuerdan.
    let base = comparar_tres(&pk_c, &ct_c, &ss_enc_c, &ss_dec_c, &r, &l);
    assert!(base.acuerdo_total(), "las tres deberían concordar: {base:?}");

    // Brazo libcrux — pk: un bit alterado debe romper pk_todas_iguales.
    let mut l_pk = LibcruxOut { pk: l.pk, ct: l.ct, ss_enc: l.ss_enc, ss_dec: l.ss_dec };
    l_pk.pk[0] ^= 0x01;
    let v = comparar_tres(&pk_c, &ct_c, &ss_enc_c, &ss_dec_c, &r, &l_pk);
    assert!(!v.pk_todas_iguales && !v.acuerdo_total(), "el brazo libcrux/pk no se compara: {v:?}");

    // Brazo libcrux — ct.
    let mut l_ct = LibcruxOut { pk: l.pk, ct: l.ct, ss_enc: l.ss_enc, ss_dec: l.ss_dec };
    l_ct.ct[0] ^= 0x01;
    let v = comparar_tres(&pk_c, &ct_c, &ss_enc_c, &ss_dec_c, &r, &l_ct);
    assert!(!v.ct_todas_iguales && !v.acuerdo_total(), "el brazo libcrux/ct no se compara: {v:?}");

    // Brazo libcrux — ss_enc.
    let mut l_ss = LibcruxOut { pk: l.pk, ct: l.ct, ss_enc: l.ss_enc, ss_dec: l.ss_dec };
    l_ss.ss_enc[0] ^= 0x01;
    let v = comparar_tres(&pk_c, &ct_c, &ss_enc_c, &ss_dec_c, &r, &l_ss);
    assert!(!v.ss_enc_todas_iguales && !v.acuerdo_total(), "el brazo libcrux/ss_enc no se compara: {v:?}");

    // Brazo quipu — ek: alterar la salida de Rust también debe romperlo.
    let mut r_ek = RustOut { ek: r.ek.clone(), ct: r.ct.clone(), ss_enc: r.ss_enc, ss_dec: r.ss_dec };
    r_ek.ek[0] ^= 0x01;
    let v = comparar_tres(&pk_c, &ct_c, &ss_enc_c, &ss_dec_c, &r_ek, &l);
    assert!(!v.pk_todas_iguales && !v.acuerdo_total(), "el brazo quipu/ek no se compara: {v:?}");

    // Brazo C — pk: alterar la referencia C debe romper el acuerdo de las tres.
    let mut pk_c_mut = pk_c;
    pk_c_mut[0] ^= 0x01;
    let v = comparar_tres(&pk_c_mut, &ct_c, &ss_enc_c, &ss_dec_c, &r, &l);
    assert!(!v.pk_todas_iguales && !v.acuerdo_total(), "el brazo C/pk no se compara: {v:?}");
}

#[test]
fn simula_128_tres_vias() {
    // D8: 128 (semilla, m) pseudo-aleatorios; acuerdo total de las TRES en cada uno.
    let mut estado = 0xB16B_00B5_1234_5678u64;
    let mut fallos = 0usize;
    for i in 0..128 {
        let mut coins = [0u8; 64];
        let mut m = [0u8; 32];
        llenar(&mut estado, &mut coins);
        llenar(&mut estado, &mut m);
        let v = diferencia_tres(&coins, &m);
        if !v.acuerdo_total() {
            eprintln!("caso {i} discrepó entre las tres: {v:?}");
            fallos += 1;
        }
    }
    assert_eq!(fallos, 0, "{fallos}/128 casos discreparon entre quipu, C y libcrux");
}
