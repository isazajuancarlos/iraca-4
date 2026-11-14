// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Diferencial de ML-DSA-87 (FIPS 204): el crate `ml-dsa` que usa quipu contra la
//! referencia C de pq-crystals (dilithium), con los mismos bytes crudos.
//!
//! Dos sutilezas resueltas frente a ML-KEM:
//!  - El keygen de dilithium NO tiene variante `_derand`: llama `randombytes`. Lo
//!    proveemos desde Rust ([`randombytes`]) leyendo una semilla controlada por
//!    hilo, así el keygen se vuelve determinista a partir de esa semilla — la
//!    MISMA que consume `SigningKey::from_seed`.
//!  - La firma se hace por `crypto_sign_signature_internal` con `rnd = 0` y
//!    `pre = [0,0]` (contexto vacío), que es exactamente lo que hace
//!    `sign_deterministic(m, b"")` en Rust. Así se evita el branch de firma
//!    aleatoria del envoltorio de alto nivel.

use core::cell::RefCell;

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Seed, Signature, Signer, SigningKey,
    Verifier, VerifyingKey,
};

// Dimensiones de ML-DSA-87 (FIPS 204).
pub const PK: usize = 2592;
pub const SK: usize = 4896;
pub const SIG: usize = 4627;
pub const SEED: usize = 32;

thread_local! {
    /// Semilla que la referencia C lee por `randombytes` en su keygen. Por hilo,
    /// para que las pruebas en paralelo no se pisen.
    static SEMILLA: RefCell<[u8; SEED]> = const { RefCell::new([0u8; SEED]) };
}

/// Fija la semilla que la referencia C leerá por `randombytes` en su keygen.
/// Compartida por el módulo 87 de aquí y el genérico `mldsa_niveles` (el símbolo
/// `randombytes` es único en todo el binario, así que la semilla también).
pub fn fijar_semilla(seed: &[u8; SEED]) {
    SEMILLA.with(|s| *s.borrow_mut() = *seed);
}

/// `randombytes` para la referencia C (kyber y dilithium comparten el símbolo).
/// Devuelve la semilla controlada por hilo. kyber nunca la llama (usa `_derand`);
/// dilithium la llama UNA vez en keygen con `outlen = 32`.
///
/// # Safety
/// `out` debe apuntar a un buffer de al menos `outlen` bytes escribibles. Es el
/// contrato de la firma C `void randombytes(uint8_t*, size_t)`.
#[no_mangle]
pub unsafe extern "C" fn randombytes(out: *mut u8, outlen: usize) {
    SEMILLA.with(|s| {
        let s = s.borrow();
        let n = outlen.min(SEED);
        // SAFETY: el llamante (código C) garantiza `out` válido para `outlen`
        // bytes escribibles, que es el contrato de `void randombytes(uint8_t*, size_t)`.
        core::ptr::copy_nonoverlapping(s.as_ptr(), out, n);
        if outlen > SEED {
            core::ptr::write_bytes(out.add(SEED), 0, outlen - SEED);
        }
    });
}

mod ffi {
    use core::ffi::c_int;
    extern "C" {
        pub fn pqcrystals_dilithium5_ref_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
        pub fn pqcrystals_dilithium5_ref_signature_internal(
            sig: *mut u8,
            siglen: *mut usize,
            m: *const u8,
            mlen: usize,
            pre: *const u8,
            prelen: usize,
            rnd: *const u8,
            sk: *const u8,
        ) -> c_int;
        pub fn pqcrystals_dilithium5_ref_verify_internal(
            sig: *const u8,
            siglen: usize,
            m: *const u8,
            mlen: usize,
            pre: *const u8,
            prelen: usize,
            pk: *const u8,
        ) -> c_int;
    }
}

// Contexto vacío: prefijo de dominio [0x00, ctxlen=0] (FIPS 204, firma pura).
const PRE: [u8; 2] = [0u8, 0u8];
const RND0: [u8; 32] = [0u8; 32];

// ---------- Referencia C (oráculo independiente) ----------

/// Keygen C determinista a partir de una semilla de 32 bytes (vía `randombytes`).
#[must_use]
pub fn c_keypair(seed: &[u8; SEED]) -> ([u8; PK], [u8; SK]) {
    SEMILLA.with(|s| *s.borrow_mut() = *seed);
    let mut pk = [0u8; PK];
    let mut sk = [0u8; SK];
    // SAFETY: buffers del tamaño exacto de ML-DSA-87.
    unsafe {
        ffi::pqcrystals_dilithium5_ref_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
    }
    (pk, sk)
}

/// Firma C determinista (rnd=0, contexto vacío).
#[must_use]
pub fn c_sign(sk: &[u8; SK], m: &[u8]) -> Vec<u8> {
    let mut sig = [0u8; SIG];
    let mut siglen = 0usize;
    // SAFETY: sig cabe CRYPTO_BYTES; punteros de m/pre/rnd/sk válidos.
    unsafe {
        ffi::pqcrystals_dilithium5_ref_signature_internal(
            sig.as_mut_ptr(),
            &mut siglen,
            m.as_ptr(),
            m.len(),
            PRE.as_ptr(),
            PRE.len(),
            RND0.as_ptr(),
            sk.as_ptr(),
        );
    }
    sig[..siglen].to_vec()
}

/// Verificación C. `true` si la firma es válida.
#[must_use]
pub fn c_verify(pk: &[u8; PK], m: &[u8], sig: &[u8]) -> bool {
    // SAFETY: punteros válidos; verify_internal no escribe.
    let r = unsafe {
        ffi::pqcrystals_dilithium5_ref_verify_internal(
            sig.as_ptr(),
            sig.len(),
            m.as_ptr(),
            m.len(),
            PRE.as_ptr(),
            PRE.len(),
            pk.as_ptr(),
        )
    };
    r == 0
}

// ---------- El crate de quipu (Rust) ----------

struct RustPar {
    sk: SigningKey<MlDsa87>,
    vk: VerifyingKey<MlDsa87>,
}

fn rust_par(seed: &[u8; SEED]) -> RustPar {
    let s = Seed::try_from(&seed[..]).expect("semilla de 32 bytes");
    let sk = SigningKey::<MlDsa87>::from_seed(&s);
    let vk = sk.verifying_key();
    RustPar { sk, vk }
}

fn rust_vk_bytes(par: &RustPar) -> Vec<u8> {
    par.vk.encode().as_slice().to_vec()
}

fn rust_sign(par: &RustPar, m: &[u8]) -> Vec<u8> {
    // El `Signer` de ml-dsa 0.1.1 usa la variante DETERMINISTA (ctx vacío, rnd=0),
    // que es exactamente lo que hace C con pre=[0,0] y rnd=0.
    par.sk.sign(m).encode().as_slice().to_vec()
}

/// Verifica con el crate de quipu una firma serializada (decodifica y verifica),
/// exactamente como lo haría un consumidor real.
#[must_use]
pub fn rust_verify(pk_bytes: &[u8], m: &[u8], sig: &[u8]) -> bool {
    let Ok(enc_vk) = EncodedVerifyingKey::<MlDsa87>::try_from(pk_bytes) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&enc_vk);
    let Ok(enc_sig) = EncodedSignature::<MlDsa87>::try_from(sig) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa87>::decode(&enc_sig) else {
        return false;
    };
    vk.verify(m, &sig).is_ok()
}

/// Veredicto de un caso diferencial ML-DSA con la misma semilla y el mismo mensaje.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Veredicto {
    pub pk_igual: bool,
    pub sig_igual: bool,
    /// Verificación cruzada: cada lado acepta la firma del otro.
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

/// Corre C y Rust con la misma semilla y el mismo mensaje, y compara cada etapa.
#[must_use]
pub fn diferencia(seed: &[u8; SEED], m: &[u8]) -> Veredicto {
    let (pk_c, sk_c) = c_keypair(seed);
    let sig_c = c_sign(&sk_c, m);

    let par = rust_par(seed);
    let pk_r = rust_vk_bytes(&par);
    let sig_r = rust_sign(&par, m);

    Veredicto {
        pk_igual: pk_r == pk_c,
        sig_igual: sig_r == sig_c,
        rust_verifica_c: rust_verify(&pk_c, m, &sig_c),
        c_verifica_rust: {
            let mut pk = [0u8; PK];
            if pk_r.len() == PK {
                pk.copy_from_slice(&pk_r);
                c_verify(&pk, m, &sig_r)
            } else {
                false
            }
        },
        rust_verifica_rust: rust_verify(&pk_r, m, &sig_r),
        c_verifica_c: c_verify(&pk_c, m, &sig_c),
    }
}

// ---------- Capa ADVERSARIA: canonicidad del hint (cross-lenguaje) ----------
//
// La firma ML-DSA-87 = c̃ (64) ‖ z (4480) ‖ hint (83 = OMEGA posiciones + K fronteras).
// FIPS 204 (HintBitUnpack) EXIGE que los bytes de posición NO usados (desde el total
// de hints hasta OMEGA) sean 0; si no, la firma es no-canónica y debe RECHAZARSE.
// Novedad frente a iraca-2 (Rust vs Rust, SECO): aquí es RustCrypto vs la referencia
// C dilithium — un desacuerdo revelaría un hueco de validación en uno de los dos.

pub const CTILDE: usize = 64;
pub const ZBYTES: usize = 4480; // L·POLYZ = 7·640
pub const OMEGA: usize = 75;

/// Convierte una firma válida en una con **hint NO canónico**: pone 0xFF en el
/// primer byte de posición NO usado (debe ser 0). `None` si no hay hueco.
#[must_use]
pub fn mutar_hint_no_canonico(sig: &[u8]) -> Option<Vec<u8>> {
    if sig.len() != SIG {
        return None;
    }
    let base = CTILDE + ZBYTES;
    let total = usize::from(sig[SIG - 1]); // última frontera acumulada = nº de hints
    if total >= OMEGA {
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

/// Veredicto de la pasada adversaria sobre el hint.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AdvHint {
    pub probadas: usize,
    pub saltadas: usize,
    pub rust_rechaza: usize,
    pub c_rechaza: usize,
    /// Uno acepta y el otro rechaza el no-canónico → HALLAZGO (hueco en uno).
    pub desacuerdos: usize,
    /// Los DOS aceptan el no-canónico → hueco compartido (HALLAZGO, maleabilidad).
    pub ambos_aceptan: usize,
}

impl AdvHint {
    #[must_use]
    pub fn limpio(&self) -> bool {
        self.desacuerdos == 0 && self.ambos_aceptan == 0
    }
}

/// Pasada adversaria de hint no-canónico, cross-lenguaje (RustCrypto vs C).
#[must_use]
pub fn adversario_hint(semillas: &[[u8; SEED]], msg: &[u8]) -> AdvHint {
    let mut r = AdvHint::default();
    for seed in semillas {
        let (pk_c, sk_c) = c_keypair(seed);
        let sig = c_sign(&sk_c, msg);
        // Control positivo: la firma VÁLIDA verifica en ambos lados.
        debug_assert!(c_verify(&pk_c, msg, &sig) && rust_verify(&pk_c, msg, &sig));

        let Some(mut_sig) = mutar_hint_no_canonico(&sig) else {
            r.saltadas += 1;
            continue;
        };
        r.probadas += 1;
        let rust_ok = rust_verify(&pk_c, msg, &mut_sig);
        let c_ok = c_verify(&pk_c, msg, &mut_sig);
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
