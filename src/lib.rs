// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! **iraca-4** — arnés diferencial de ML-KEM (FIPS 203).
//!
//! Compara la implementación de ML-KEM-768 que **quipu usa de verdad** (el crate
//! `ml-kem` vendorizado, vía path dep) contra la **referencia C independiente**
//! de pq-crystals (kyber), alimentando los MISMOS bytes crudos a las dos por sus
//! variantes deterministas (`_derand` en C, `from_seed`/`encapsulate_deterministic`
//! en Rust). No hay DRBG ni vectores `.rsp`: el determinismo es de extremo a
//! extremo, así que cualquier discrepancia es una discrepancia REAL entre las dos
//! implementaciones, no ruido de aleatoriedad.
//!
//! Sigue el patrón nexus: la parte frágil/ajena (C) se aísla tras un módulo `ffi`
//! delgado y se invoca como oráculo; el resto es Rust seguro.

use ml_kem::kem::Decapsulate;
use ml_kem::{B32, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, Seed};

pub mod adversario;
pub mod mldsa;
pub mod mldsa_niveles;
pub mod mlkem;

// Dimensiones de ML-KEM-768 (FIPS 203).
pub const PK: usize = 1184; // clave de encapsulación (ek)
pub const SK: usize = 2400; // clave de decapsulación KEM (dk)
pub const CT: usize = 1088; // texto cifrado
pub const SS: usize = 32; // clave compartida
pub const COINS_KEYPAIR: usize = 64; // d ‖ z
pub const COINS_ENC: usize = 32; // m

mod ffi {
    use core::ffi::c_int;
    extern "C" {
        pub fn pqcrystals_kyber768_ref_keypair_derand(
            pk: *mut u8,
            sk: *mut u8,
            coins: *const u8,
        ) -> c_int;
        pub fn pqcrystals_kyber768_ref_enc_derand(
            ct: *mut u8,
            ss: *mut u8,
            pk: *const u8,
            coins: *const u8,
        ) -> c_int;
        pub fn pqcrystals_kyber768_ref_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
}

// ---------- Referencia C (oráculo independiente) ----------

/// Genera una keypair con la referencia C a partir de `coins = d‖z` (64 bytes).
#[must_use]
pub fn c_keypair(coins: &[u8; COINS_KEYPAIR]) -> ([u8; PK], [u8; SK]) {
    let mut pk = [0u8; PK];
    let mut sk = [0u8; SK];
    // SAFETY: los tres buffers tienen el tamaño exacto que la función C escribe
    // (KYBER_K=3), y `coins` es de 64 bytes como exige `keypair_derand`.
    unsafe {
        ffi::pqcrystals_kyber768_ref_keypair_derand(pk.as_mut_ptr(), sk.as_mut_ptr(), coins.as_ptr());
    }
    (pk, sk)
}

/// Encapsula con la referencia C usando `pk` y `coins = m` (32 bytes).
#[must_use]
pub fn c_enc(pk: &[u8; PK], coins: &[u8; COINS_ENC]) -> ([u8; CT], [u8; SS]) {
    let mut ct = [0u8; CT];
    let mut ss = [0u8; SS];
    // SAFETY: buffers del tamaño exacto; pk de 1184 y coins de 32.
    unsafe {
        ffi::pqcrystals_kyber768_ref_enc_derand(
            ct.as_mut_ptr(),
            ss.as_mut_ptr(),
            pk.as_ptr(),
            coins.as_ptr(),
        );
    }
    (ct, ss)
}

/// Decapsula con la referencia C usando `ct` y la `sk` KEM.
#[must_use]
pub fn c_dec(ct: &[u8; CT], sk: &[u8; SK]) -> [u8; SS] {
    let mut ss = [0u8; SS];
    // SAFETY: buffers del tamaño exacto.
    unsafe {
        ffi::pqcrystals_kyber768_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr());
    }
    ss
}

// ---------- El crate de quipu (Rust) ----------

/// Resultado de un round-trip completo por el lado Rust (el crate de quipu).
pub struct RustOut {
    pub ek: Vec<u8>,      // clave de encapsulación serializada (debe == pk de C)
    pub ct: Vec<u8>,      // texto cifrado (debe == ct de C con el mismo m)
    pub ss_enc: [u8; SS], // clave compartida producida al encapsular
    pub ss_dec: [u8; SS], // clave compartida recuperada al decapsular
}

/// Round-trip ML-KEM-768 con el crate `ml-kem` de quipu, determinista a partir
/// de la misma semilla y el mismo `m` que se le dan a C.
#[must_use]
pub fn rust_roundtrip(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> RustOut {
    let mut seed = Seed::default();
    seed.copy_from_slice(coins);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);

    let ek: EncapsulationKey<MlKem768> = dk.encapsulation_key().clone();
    let ek_bytes = ek.to_bytes();

    let mut mm = B32::default();
    mm.copy_from_slice(m);
    let (ct, ss_enc) = ek.encapsulate_deterministic(&mm);

    // En ML-KEM la decapsulación es infalible (rechazo implícito): devuelve la
    // clave compartida directamente, no un Result.
    let ss_dec = dk.decapsulate(&ct);

    RustOut {
        ek: ek_bytes.as_slice().to_vec(),
        ct: ct.as_slice().to_vec(),
        ss_enc: to_arr(ss_enc.as_slice()),
        ss_dec: to_arr(ss_dec.as_slice()),
    }
}

fn to_arr(s: &[u8]) -> [u8; SS] {
    let mut a = [0u8; SS];
    a.copy_from_slice(s);
    a
}

// ---------- libcrux (2º oráculo: Rust puro, formalmente verificado) ----------

/// Salida de un round-trip completo por libcrux (Cryspen/HACL*).
///
/// libcrux es un oráculo INDEPENDIENTE del de pq-crystals: distinto equipo,
/// distinto codebase, y con **verificación formal** de la corrección funcional.
/// Que quipu coincida con AMBOS es una señal mucho más fuerte que con uno solo:
/// un oráculo puede compartir el punto ciego del código medido, dos que no se
/// conocen entre sí, casi nunca ([[nexus-firma-no-verificada-punto-ciego-del-control]]).
pub struct LibcruxOut {
    pub pk: [u8; PK],     // clave de encapsulación (debe == pk de C == ek de quipu)
    pub ct: [u8; CT],     // texto cifrado (debe == ct de C con el mismo m)
    pub ss_enc: [u8; SS], // clave compartida al encapsular
    pub ss_dec: [u8; SS], // clave compartida recuperada al decapsular
}

/// Round-trip ML-KEM-768 con libcrux, determinista a partir de la MISMA semilla
/// (`coins = d‖z`) y el mismo `m` que se le dan a C y a quipu. La API de libcrux
/// toma el azar como argumento explícito (`generate_key_pair([u8;64])`,
/// `encapsulate(pk, [u8;32])`), que es exactamente el patrón `_derand`.
#[must_use]
pub fn libcrux_roundtrip(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> LibcruxOut {
    use libcrux_ml_kem::mlkem768;
    let kp = mlkem768::generate_key_pair(*coins);
    // encapsula contra su PROPIA pk (que es byte-idéntica a la de C/quipu con el
    // mismo `coins`; el banco lo verifica): round-trip autocontenido, sin inyectar
    // clave ajena.
    let (ct, ss_enc) = mlkem768::encapsulate(kp.public_key(), *m);
    let ss_dec = mlkem768::decapsulate(kp.private_key(), &ct);
    LibcruxOut {
        pk: *kp.pk(),
        ct: *ct.as_slice(),
        ss_enc,
        ss_dec,
    }
}

/// El veredicto de un caso diferencial: en qué punto (si alguno) discreparon C y
/// Rust con la MISMA entrada.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Veredicto {
    pub ek_igual: bool,
    pub ct_igual: bool,
    pub ss_enc_igual: bool,
    pub ss_dec_igual: bool,
    /// El round-trip cerró en ambos lados (ss_enc == ss_dec dentro de cada impl).
    pub roundtrip_c: bool,
    pub roundtrip_rust: bool,
}

impl Veredicto {
    /// Todo coincide y ambos round-trips cierran: acuerdo total.
    #[must_use]
    pub fn acuerdo_total(&self) -> bool {
        self.ek_igual
            && self.ct_igual
            && self.ss_enc_igual
            && self.ss_dec_igual
            && self.roundtrip_c
            && self.roundtrip_rust
    }
}

/// Corre C y Rust con la misma semilla y el mismo `m`, y compara cada etapa.
#[must_use]
pub fn diferencia(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Veredicto {
    let (pk_c, sk_c) = c_keypair(coins);
    let (ct_c, ss_enc_c) = c_enc(&pk_c, m);
    let ss_dec_c = c_dec(&ct_c, &sk_c);

    let r = rust_roundtrip(coins, m);

    Veredicto {
        ek_igual: r.ek == pk_c,
        ct_igual: r.ct == ct_c,
        ss_enc_igual: r.ss_enc == ss_enc_c,
        ss_dec_igual: r.ss_dec == ss_dec_c,
        roundtrip_c: ss_enc_c == ss_dec_c,
        roundtrip_rust: r.ss_enc == r.ss_dec,
    }
}

/// Veredicto de un caso diferencial de TRES vías: quipu (`ml-kem`) contra sus dos
/// oráculos independientes, la referencia C de pq-crystals y libcrux. Un campo es
/// `true` solo si las TRES implementaciones producen el mismo valor en esa etapa.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct VeredictoTres {
    pub pk_todas_iguales: bool,
    pub ct_todas_iguales: bool,
    pub ss_enc_todas_iguales: bool,
    pub ss_dec_todas_iguales: bool,
    /// Cada implementación cierra su propio round-trip (ss_enc == ss_dec).
    pub roundtrip_c: bool,
    pub roundtrip_rust: bool,
    pub roundtrip_libcrux: bool,
}

impl VeredictoTres {
    /// Las tres coinciden en todas las etapas y las tres cierran su round-trip.
    #[must_use]
    pub fn acuerdo_total(&self) -> bool {
        self.pk_todas_iguales
            && self.ct_todas_iguales
            && self.ss_enc_todas_iguales
            && self.ss_dec_todas_iguales
            && self.roundtrip_c
            && self.roundtrip_rust
            && self.roundtrip_libcrux
    }
}

/// Corre las TRES implementaciones con la misma semilla y el mismo `m`, y exige
/// acuerdo byte a byte entre las tres en cada etapa. Si dos cualesquiera difieren
/// en el mismo bit, no es casualidad de una implementación: es un bug real.
#[must_use]
pub fn diferencia_tres(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> VeredictoTres {
    let (pk_c, sk_c) = c_keypair(coins);
    let (ct_c, ss_enc_c) = c_enc(&pk_c, m);
    let ss_dec_c = c_dec(&ct_c, &sk_c);

    let r = rust_roundtrip(coins, m);
    let l = libcrux_roundtrip(coins, m);

    comparar_tres(&pk_c, &ct_c, &ss_enc_c, &ss_dec_c, &r, &l)
}

/// Compara las salidas ya calculadas de las tres implementaciones y produce el
/// veredicto. Es la LÓGICA de comparación de `diferencia_tres`, extraída para que
/// se pueda clavar en el repo que cada brazo (C, quipu, libcrux) se compara de
/// verdad — que ningún `&& x == y` está muerto a `&& true` (D33). Se compara todo
/// como slices para que C (arrays), quipu (`Vec`) y libcrux (arrays) entren a la
/// misma comparación sin ambigüedad de tipos.
#[must_use]
pub fn comparar_tres(
    pk_c: &[u8; PK],
    ct_c: &[u8; CT],
    ss_enc_c: &[u8; SS],
    ss_dec_c: &[u8; SS],
    r: &RustOut,
    l: &LibcruxOut,
) -> VeredictoTres {
    let pk = pk_c.as_slice();
    let ct = ct_c.as_slice();

    VeredictoTres {
        pk_todas_iguales: r.ek.as_slice() == pk && l.pk.as_slice() == pk,
        ct_todas_iguales: r.ct.as_slice() == ct && l.ct.as_slice() == ct,
        ss_enc_todas_iguales: r.ss_enc == *ss_enc_c && l.ss_enc == *ss_enc_c,
        ss_dec_todas_iguales: r.ss_dec == *ss_dec_c && l.ss_dec == *ss_dec_c,
        roundtrip_c: ss_enc_c == ss_dec_c,
        roundtrip_rust: r.ss_enc == r.ss_dec,
        roundtrip_libcrux: l.ss_enc == l.ss_dec,
    }
}
