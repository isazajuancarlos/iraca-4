// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Diferencial GENÉRICO de ML-DSA (FIPS 204) sobre los TRES niveles —
//! ML-DSA-44/65/87— entre el crate `ml-dsa` que usa quipu y la referencia C de
//! pq-crystals (dilithium), con los mismos bytes crudos deterministas.
//!
//! Es la forma del módulo 87 de `lib.rs`/`mldsa.rs` generalizada con un
//! `macro_rules!`: una sola expresión del cableado (keygen determinista por
//! `randombytes` con semilla controlada, firma determinista `rnd=0`/`pre=[0,0]`,
//! verificación cruzada), instanciada con el tipo `ml-dsa` y los símbolos C de
//! cada nivel. Incluye la capa ADVERSARIA de canonicidad del hint por nivel.
//!
//! **AWS-LC NO entra como oráculo de firma** aquí: su firma ML-DSA es *hedged*
//! (aleatoria) y no expone por la vía bindeada la variante determinista `rnd=0`,
//! así que las firmas no son byte-comparables. Solo serviría como keygen
//! byte-exacto y verificador cruzado; se deja fuera por ahora.

use core::ffi::c_int;

use crate::mldsa::fijar_semilla;

/// Semilla `xi` del keygen: 32 B en todos los niveles.
pub const SEED: usize = 32;

// Contexto vacío (FIPS 204 firma pura): prefijo de dominio [0x00, ctxlen=0].
const PRE: [u8; 2] = [0u8, 0u8];
// Firma determinista: rnd = 0 (RNDBYTES = 32; la referencia lee 32 B de aquí).
const RND0: [u8; 32] = [0u8; 32];

// Firmas C, idénticas en los tres niveles (solo cambian los símbolos).
type FnKeypair = unsafe extern "C" fn(*mut u8, *mut u8) -> c_int;
type FnSign = unsafe extern "C" fn(
    *mut u8,   // sig
    *mut usize, // siglen
    *const u8, // m
    usize,     // mlen
    *const u8, // pre
    usize,     // prelen
    *const u8, // rnd
    *const u8, // sk
) -> c_int;
type FnVerify = unsafe extern "C" fn(
    *const u8, // sig
    usize,     // siglen
    *const u8, // m
    usize,     // mlen
    *const u8, // pre
    usize,     // prelen
    *const u8, // pk
) -> c_int;

/// Enlace a la referencia C de dilithium para UN nivel.
struct BindingDsa {
    pk_len: usize,
    sk_len: usize,
    sig_len: usize,
    keypair: FnKeypair,
    sign: FnSign,
    verify: FnVerify,
}

/// Keygen C determinista a partir de la semilla de 32 B (vía `randombytes`).
///
/// # Safety
/// Los símbolos de `b` deben ser los de dilithium del nivel cuyos tamaños son
/// `b.pk_len`/`b.sk_len`; esas funciones escriben exactamente esos tamaños.
unsafe fn c_keypair_raw(b: &BindingDsa, seed: &[u8; SEED]) -> (Vec<u8>, Vec<u8>) {
    fijar_semilla(seed);
    let mut pk = vec![0u8; b.pk_len];
    let mut sk = vec![0u8; b.sk_len];
    (b.keypair)(pk.as_mut_ptr(), sk.as_mut_ptr());
    (pk, sk)
}

/// Firma C determinista (rnd=0, contexto vacío) por `signature_internal`.
///
/// # Safety
/// `sk` es la sk del nivel de `b`; `sig` se dimensiona a `b.sig_len`.
unsafe fn c_sign_raw(b: &BindingDsa, sk: &[u8], m: &[u8]) -> Vec<u8> {
    let mut sig = vec![0u8; b.sig_len];
    let mut siglen = 0usize;
    (b.sign)(
        sig.as_mut_ptr(),
        &mut siglen,
        m.as_ptr(),
        m.len(),
        PRE.as_ptr(),
        PRE.len(),
        RND0.as_ptr(),
        sk.as_ptr(),
    );
    sig.truncate(siglen);
    sig
}

/// Verificación C. `true` si la firma es válida.
///
/// # Safety
/// Punteros válidos; `verify_internal` no escribe.
unsafe fn c_verify_raw(b: &BindingDsa, pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    (b.verify)(
        sig.as_ptr(),
        sig.len(),
        m.as_ptr(),
        m.len(),
        PRE.as_ptr(),
        PRE.len(),
        pk.as_ptr(),
    ) == 0
}

mod ffi {
    use core::ffi::c_int;
    macro_rules! decl {
        ($kp:ident, $sig:ident, $ver:ident) => {
            extern "C" {
                pub fn $kp(pk: *mut u8, sk: *mut u8) -> c_int;
                pub fn $sig(
                    sig: *mut u8, siglen: *mut usize, m: *const u8, mlen: usize,
                    pre: *const u8, prelen: usize, rnd: *const u8, sk: *const u8,
                ) -> c_int;
                pub fn $ver(
                    sig: *const u8, siglen: usize, m: *const u8, mlen: usize,
                    pre: *const u8, prelen: usize, pk: *const u8,
                ) -> c_int;
            }
        };
    }
    decl!(
        pqcrystals_dilithium2_ref_keypair,
        pqcrystals_dilithium2_ref_signature_internal,
        pqcrystals_dilithium2_ref_verify_internal
    );
    decl!(
        pqcrystals_dilithium3_ref_keypair,
        pqcrystals_dilithium3_ref_signature_internal,
        pqcrystals_dilithium3_ref_verify_internal
    );
    decl!(
        pqcrystals_dilithium5_ref_keypair,
        pqcrystals_dilithium5_ref_signature_internal,
        pqcrystals_dilithium5_ref_verify_internal
    );
}

/// Un nivel de ML-DSA: tamaños, layout de la firma (para el ataque de hint) y las
/// dos vías (referencia C, crate `ml-dsa` de quipu).
pub trait NivelDsa {
    const NOMBRE: &'static str;
    const PK: usize;
    const SK: usize;
    const SIG: usize;
    /// Bytes de `c̃` al inicio de la firma.
    const CTILDE: usize;
    /// Bytes de `z` (= L · POLYZ_PACKEDBYTES).
    const ZBYTES: usize;
    /// Máximo de posiciones de hint (frontera del relleno que DEBE ser 0).
    const OMEGA: usize;

    fn c_keypair(seed: &[u8; SEED]) -> (Vec<u8>, Vec<u8>);
    fn c_sign(sk: &[u8], m: &[u8]) -> Vec<u8>;
    fn c_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> bool;
    /// Keygen + firma determinista con el crate de quipu. Devuelve `(pk, sig)`.
    fn rust_keypair_sign(seed: &[u8; SEED], m: &[u8]) -> (Vec<u8>, Vec<u8>);
    fn rust_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> bool;
}

macro_rules! nivel_dsa {
    ($nombre:ident, $etq:literal, $mld:ty, $pk:expr, $sk:expr, $sig:expr,
     $ctilde:expr, $zbytes:expr, $omega:expr,
     $c_kp:path, $c_sign:path, $c_ver:path) => {
        pub struct $nombre;

        impl NivelDsa for $nombre {
            const NOMBRE: &'static str = $etq;
            const PK: usize = $pk;
            const SK: usize = $sk;
            const SIG: usize = $sig;
            const CTILDE: usize = $ctilde;
            const ZBYTES: usize = $zbytes;
            const OMEGA: usize = $omega;

            fn c_keypair(seed: &[u8; SEED]) -> (Vec<u8>, Vec<u8>) {
                let b = BindingDsa {
                    pk_len: Self::PK, sk_len: Self::SK, sig_len: Self::SIG,
                    keypair: $c_kp, sign: $c_sign, verify: $c_ver,
                };
                // SAFETY: símbolos y tamaños del MISMO nivel.
                unsafe { c_keypair_raw(&b, seed) }
            }
            fn c_sign(sk: &[u8], m: &[u8]) -> Vec<u8> {
                let b = BindingDsa {
                    pk_len: Self::PK, sk_len: Self::SK, sig_len: Self::SIG,
                    keypair: $c_kp, sign: $c_sign, verify: $c_ver,
                };
                // SAFETY: sk del nivel de `b`.
                unsafe { c_sign_raw(&b, sk, m) }
            }
            fn c_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
                let b = BindingDsa {
                    pk_len: Self::PK, sk_len: Self::SK, sig_len: Self::SIG,
                    keypair: $c_kp, sign: $c_sign, verify: $c_ver,
                };
                // SAFETY: punteros válidos; verify no escribe.
                unsafe { c_verify_raw(&b, pk, m, sig) }
            }
            fn rust_keypair_sign(seed: &[u8; SEED], m: &[u8]) -> (Vec<u8>, Vec<u8>) {
                use ml_dsa::{Keypair, Seed, Signer, SigningKey};
                let s = Seed::try_from(&seed[..]).expect("semilla de 32 bytes");
                let sk = SigningKey::<$mld>::from_seed(&s);
                let vk = sk.verifying_key();
                let pk = vk.encode().as_slice().to_vec();
                // El `Signer` de ml-dsa usa la variante DETERMINISTA (ctx vacío,
                // rnd=0), lo mismo que C con pre=[0,0] y rnd=0.
                let sig = sk.sign(m).encode().as_slice().to_vec();
                (pk, sig)
            }
            fn rust_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
                use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, Verifier, VerifyingKey};
                let Ok(enc_vk) = EncodedVerifyingKey::<$mld>::try_from(pk) else {
                    return false;
                };
                let vk = VerifyingKey::<$mld>::decode(&enc_vk);
                let Ok(enc_sig) = EncodedSignature::<$mld>::try_from(sig) else {
                    return false;
                };
                let Some(sig) = Signature::<$mld>::decode(&enc_sig) else {
                    return false;
                };
                vk.verify(m, &sig).is_ok()
            }
        }
    };
}

nivel_dsa!(
    Dsa44, "ML-DSA-44", ml_dsa::MlDsa44, 1312, 2560, 2420, 32, 2304, 80,
    ffi::pqcrystals_dilithium2_ref_keypair,
    ffi::pqcrystals_dilithium2_ref_signature_internal,
    ffi::pqcrystals_dilithium2_ref_verify_internal
);
nivel_dsa!(
    Dsa65, "ML-DSA-65", ml_dsa::MlDsa65, 1952, 4032, 3309, 48, 3200, 55,
    ffi::pqcrystals_dilithium3_ref_keypair,
    ffi::pqcrystals_dilithium3_ref_signature_internal,
    ffi::pqcrystals_dilithium3_ref_verify_internal
);
nivel_dsa!(
    Dsa87, "ML-DSA-87", ml_dsa::MlDsa87, 2592, 4896, 4627, 64, 4480, 75,
    ffi::pqcrystals_dilithium5_ref_keypair,
    ffi::pqcrystals_dilithium5_ref_signature_internal,
    ffi::pqcrystals_dilithium5_ref_verify_internal
);

/// Veredicto del diferencial de dos vías (quipu ↔ referencia C).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Veredicto {
    pub pk_igual: bool,
    pub sig_igual: bool,
    /// Cada lado acepta la firma del otro.
    pub rust_verifica_c: bool,
    pub c_verifica_rust: bool,
    /// Cada lado se verifica a sí mismo.
    pub rust_verifica_rust: bool,
    pub c_verifica_c: bool,
}

impl Veredicto {
    #[must_use]
    pub fn acuerdo_total(&self) -> bool {
        self.pk_igual
            && self.sig_igual
            && self.rust_verifica_c
            && self.c_verifica_rust
            && self.rust_verifica_rust
            && self.c_verifica_c
    }
}

/// Corre C y quipu con la misma semilla y mensaje, compara pk y firma byte a byte
/// y cruza las verificaciones.
#[must_use]
pub fn diferencia<N: NivelDsa>(seed: &[u8; SEED], m: &[u8]) -> Veredicto {
    let (pk_c, sk_c) = N::c_keypair(seed);
    let sig_c = N::c_sign(&sk_c, m);
    let (pk_r, sig_r) = N::rust_keypair_sign(seed, m);

    Veredicto {
        pk_igual: pk_r == pk_c,
        sig_igual: sig_r == sig_c,
        rust_verifica_c: N::rust_verify(&pk_c, m, &sig_c),
        c_verifica_rust: N::c_verify(&pk_r, m, &sig_r),
        rust_verifica_rust: N::rust_verify(&pk_r, m, &sig_r),
        c_verifica_c: N::c_verify(&pk_c, m, &sig_c),
    }
}

// ---------- Capa ADVERSARIA: canonicidad del hint (cross-lenguaje) ----------

/// Convierte una firma válida en una con **hint NO canónico**: pone 0xFF en el
/// primer byte de posición NO usado (que FIPS 204 exige a 0). `None` si no hay
/// hueco. El layout es `c̃ ‖ z ‖ hint`; el último byte de la firma es la frontera
/// acumulada = número de hints usados.
#[must_use]
pub fn mutar_hint_no_canonico<N: NivelDsa>(sig: &[u8]) -> Option<Vec<u8>> {
    if sig.len() != N::SIG {
        return None;
    }
    let base = N::CTILDE + N::ZBYTES;
    let total = usize::from(sig[N::SIG - 1]);
    if total >= N::OMEGA {
        return None;
    }
    let idx = base + total;
    if sig[idx] != 0 {
        return None;
    }
    let mut m = sig.to_vec();
    m[idx] = 0xFF;
    Some(m)
}

/// Veredicto de la pasada adversaria del hint.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AdvHint {
    pub probadas: usize,
    pub saltadas: usize,
    pub rust_rechaza: usize,
    pub c_rechaza: usize,
    /// Uno acepta y el otro rechaza → HALLAZGO (hueco de validación en uno).
    pub desacuerdos: usize,
    /// Los dos aceptan → hueco compartido (HALLAZGO, maleabilidad).
    pub ambos_aceptan: usize,
}

impl AdvHint {
    #[must_use]
    pub fn limpio(&self) -> bool {
        self.desacuerdos == 0 && self.ambos_aceptan == 0
    }
}

/// Pasada adversaria de hint no-canónico, cross-lenguaje (RustCrypto vs C), para
/// el nivel `N`.
#[must_use]
pub fn adversario_hint<N: NivelDsa>(semillas: &[[u8; SEED]], msg: &[u8]) -> AdvHint {
    let mut r = AdvHint::default();
    for seed in semillas {
        let (pk_c, sk_c) = N::c_keypair(seed);
        let sig = N::c_sign(&sk_c, msg);
        // Control positivo (D30): la firma VÁLIDA verifica en ambos lados. Va como
        // `assert!` (no `debug_assert!`) para que también corra bajo `--release`.
        assert!(
            N::c_verify(&pk_c, msg, &sig) && N::rust_verify(&pk_c, msg, &sig),
            "control positivo: la firma válida no verifica en ambos lados"
        );

        let Some(mut_sig) = mutar_hint_no_canonico::<N>(&sig) else {
            r.saltadas += 1;
            continue;
        };
        r.probadas += 1;
        let rust_ok = N::rust_verify(&pk_c, msg, &mut_sig);
        let c_ok = N::c_verify(&pk_c, msg, &mut_sig);
        if !rust_ok {
            r.rust_rechaza += 1;
        }
        if !c_ok {
            r.c_rechaza += 1;
        }
        if rust_ok && c_ok {
            r.ambos_aceptan += 1;
        } else if rust_ok != c_ok {
            r.desacuerdos += 1;
        }
    }
    r
}
