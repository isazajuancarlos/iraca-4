// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Diferencial GENÉRICO de ML-KEM (FIPS 203) sobre los TRES niveles —
//! ML-KEM-512/768/1024— contra los mismos oráculos que el módulo 768 de `lib.rs`:
//! la referencia C de pq-crystals (kyber) y libcrux (Rust verificado), frente al
//! crate `ml-kem` que usa quipu.
//!
//! La forma es la misma de `lib.rs` (mismos bytes crudos deterministas a las tres
//! por sus entradas `_derand`), pero aquí el cableado por nivel se genera con UN
//! `macro_rules!` —una sola expresión de "cómo se conduce ML-KEM", instanciada con
//! los tipos y símbolos de cada nivel (D9: no se copia, se expande)— y la LÓGICA de
//! comparación es genérica sobre una [`Salida`] uniforme, común a los tres niveles.

use core::ffi::c_int;

/// Tamaño de la clave compartida (32 B en todos los niveles de ML-KEM).
pub const SS: usize = 32;
/// Semilla del keygen: `d ‖ z` (64 B en todos los niveles).
pub const COINS_KEYPAIR: usize = 64;
/// Aleatoriedad del encaps: `m` (32 B en todos los niveles).
pub const COINS_ENC: usize = 32;

/// Salida uniforme de un round-trip por cualquiera de las tres implementaciones.
/// Se guardan como `Vec` los campos cuyo tamaño depende del nivel (pk, ct) para
/// que la comparación sea la misma sin genéricos de tamaño.
#[derive(Clone, Debug)]
pub struct Salida {
    pub pk: Vec<u8>,
    pub ct: Vec<u8>,
    pub ss_enc: [u8; SS],
    pub ss_dec: [u8; SS],
}

/// Un nivel de ML-KEM: ata sus tamaños, su NID en AWS-LC y las CUATRO vías de
/// round-trip determinista.
pub trait NivelKem {
    const NOMBRE: &'static str;
    const PK: usize;
    const SK: usize;
    const CT: usize;
    /// NID del nivel en AWS-LC (`NID_MLKEM512/768/1024`).
    const NID_KEM: c_int;
    /// Referencia C de pq-crystals (kyber) por sus variantes `_derand`.
    fn c(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida;
    /// El crate `ml-kem` que usa quipu (Rust).
    fn rust(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida;
    /// libcrux (Cryspen/HACL*, Rust formalmente verificado).
    fn libcrux(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida;
    /// AWS-LC (implementación C de producción) por su API determinista `EVP_PKEY`.
    fn aws(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida;
}

fn to_arr(s: &[u8]) -> [u8; SS] {
    let mut a = [0u8; SS];
    a.copy_from_slice(s);
    a
}

// Firmas C, idénticas en los tres niveles (solo cambian los símbolos namespaceados).
type FnKeypair = unsafe extern "C" fn(*mut u8, *mut u8, *const u8) -> c_int;
type FnEnc = unsafe extern "C" fn(*mut u8, *mut u8, *const u8, *const u8) -> c_int;
type FnDec = unsafe extern "C" fn(*mut u8, *const u8, *const u8) -> c_int;

/// Enlace a la referencia C de kyber para UN nivel: sus tamaños y sus tres
/// símbolos `_derand`/`_dec`. Agrupa lo que cambia entre niveles en un solo valor.
struct BindingC {
    pk_len: usize,
    sk_len: usize,
    ct_len: usize,
    keypair: FnKeypair,
    enc: FnEnc,
    dec: FnDec,
}

/// Round-trip completo por la referencia C, común a los tres niveles.
///
/// # Safety
/// Los tres símbolos de `b` deben ser las variantes `_derand`/`_dec` de kyber del
/// nivel cuyos tamaños son `b.pk_len`/`b.sk_len`/`b.ct_len`; esas funciones
/// escriben exactamente esos tamaños. `coins` es de 64 B y `m` de 32 B.
unsafe fn c_roundtrip_raw(b: &BindingC, coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida {
    let mut pk = vec![0u8; b.pk_len];
    let mut sk = vec![0u8; b.sk_len];
    (b.keypair)(pk.as_mut_ptr(), sk.as_mut_ptr(), coins.as_ptr());

    let mut ct = vec![0u8; b.ct_len];
    let mut ss_enc = [0u8; SS];
    (b.enc)(ct.as_mut_ptr(), ss_enc.as_mut_ptr(), pk.as_ptr(), m.as_ptr());

    let mut ss_dec = [0u8; SS];
    (b.dec)(ss_dec.as_mut_ptr(), ct.as_ptr(), sk.as_ptr());

    Salida { pk, ct, ss_enc, ss_dec }
}

/// Round-trip completo por AWS-LC (C de producción) vía su API determinista
/// `EVP_PKEY`. Es genérica por nivel: solo cambia el `nid`. Encapsula contra su
/// propia clave (byte-idéntica a la de los otros con el mismo `coins`).
///
/// Panica si cualquier llamada de AWS-LC falla: un oráculo que "no corrió" no
/// puede pasar por acuerdo (D30). En un arnés de prueba es el comportamiento
/// correcto — un fallo ruidoso, no un cero silencioso.
///
/// # Safety
/// `pk_len`/`ct_len` deben ser los del nivel de `nid`. `coins` es de 64 B, `m` de 32 B.
unsafe fn aws_roundtrip(
    nid: c_int,
    pk_len: usize,
    ct_len: usize,
    coins: &[u8; COINS_KEYPAIR],
    m: &[u8; COINS_ENC],
) -> Salida {
    use aws_lc_sys as sys;
    use core::ptr;

    // KEYGEN determinista desde coins = d‖z (64 B).
    let ctx = sys::EVP_PKEY_CTX_new_id(sys::EVP_PKEY_KEM, ptr::null_mut());
    assert!(!ctx.is_null(), "AWS-LC: EVP_PKEY_CTX_new_id devolvió null");
    assert_eq!(sys::EVP_PKEY_keygen_init(ctx), 1, "AWS-LC: keygen_init");
    assert_eq!(sys::EVP_PKEY_CTX_kem_set_params(ctx, nid), 1, "AWS-LC: kem_set_params");
    let mut pkey: *mut sys::EVP_PKEY = ptr::null_mut();
    let mut seed_len = coins.len();
    assert_eq!(
        sys::EVP_PKEY_keygen_deterministic(ctx, &mut pkey, coins.as_ptr(), &mut seed_len),
        1,
        "AWS-LC: keygen_deterministic"
    );
    assert!(!pkey.is_null(), "AWS-LC: pkey null tras keygen");

    // pk cruda (para comparar byte a byte con los otros oráculos).
    let mut pk = vec![0u8; pk_len];
    let mut pkl = pk_len;
    assert_eq!(
        sys::EVP_PKEY_get_raw_public_key(pkey, pk.as_mut_ptr(), &mut pkl),
        1,
        "AWS-LC: get_raw_public_key"
    );
    assert_eq!(pkl, pk_len, "AWS-LC: longitud de pk inesperada");

    // ENCAPS determinista desde m (32 B), contra su propia pk.
    let ectx = sys::EVP_PKEY_CTX_new(pkey, ptr::null_mut());
    assert!(!ectx.is_null(), "AWS-LC: CTX_new (encaps) null");
    let mut ct = vec![0u8; ct_len];
    let mut ss_enc = [0u8; SS];
    let mut ctl = ct_len;
    let mut ssl = SS;
    let mut ml = m.len();
    assert_eq!(
        sys::EVP_PKEY_encapsulate_deterministic(
            ectx,
            ct.as_mut_ptr(),
            &mut ctl,
            ss_enc.as_mut_ptr(),
            &mut ssl,
            m.as_ptr(),
            &mut ml,
        ),
        1,
        "AWS-LC: encapsulate_deterministic"
    );

    // DECAPS (determinista por diseño, sin semilla).
    let dctx = sys::EVP_PKEY_CTX_new(pkey, ptr::null_mut());
    assert!(!dctx.is_null(), "AWS-LC: CTX_new (decaps) null");
    let mut ss_dec = [0u8; SS];
    let mut ssl2 = SS;
    assert_eq!(
        sys::EVP_PKEY_decapsulate(dctx, ss_dec.as_mut_ptr(), &mut ssl2, ct.as_ptr(), ct.len()),
        1,
        "AWS-LC: decapsulate"
    );

    sys::EVP_PKEY_CTX_free(ctx);
    sys::EVP_PKEY_CTX_free(ectx);
    sys::EVP_PKEY_CTX_free(dctx);
    sys::EVP_PKEY_free(pkey);

    Salida { pk, ct, ss_enc, ss_dec }
}

mod ffi {
    use core::ffi::c_int;
    extern "C" {
        pub fn pqcrystals_kyber512_ref_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> c_int;
        pub fn pqcrystals_kyber512_ref_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> c_int;
        pub fn pqcrystals_kyber512_ref_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

        pub fn pqcrystals_kyber768_ref_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> c_int;
        pub fn pqcrystals_kyber768_ref_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> c_int;
        pub fn pqcrystals_kyber768_ref_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;

        pub fn pqcrystals_kyber1024_ref_keypair_derand(pk: *mut u8, sk: *mut u8, coins: *const u8) -> c_int;
        pub fn pqcrystals_kyber1024_ref_enc_derand(ct: *mut u8, ss: *mut u8, pk: *const u8, coins: *const u8) -> c_int;
        pub fn pqcrystals_kyber1024_ref_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> c_int;
    }
}

/// Genera `struct $nombre; impl NivelKem for $nombre` para un nivel, instanciando
/// las tres vías con el tipo de `ml-kem`, el módulo de libcrux y los símbolos C
/// del nivel. Es la ÚNICA expresión del cableado; los tres niveles la comparten.
macro_rules! nivel_kem {
    ($nombre:ident, $etq:literal, $mlk:ty, $lc:ident, $pk:expr, $sk:expr, $ct:expr,
     $nid:expr, $c_kp:path, $c_enc:path, $c_dec:path) => {
        pub struct $nombre;

        impl NivelKem for $nombre {
            const NOMBRE: &'static str = $etq;
            const PK: usize = $pk;
            const SK: usize = $sk;
            const CT: usize = $ct;
            const NID_KEM: c_int = $nid;

            fn c(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida {
                let b = BindingC {
                    pk_len: Self::PK,
                    sk_len: Self::SK,
                    ct_len: Self::CT,
                    keypair: $c_kp,
                    enc: $c_enc,
                    dec: $c_dec,
                };
                // SAFETY: los símbolos y los tamaños son los del MISMO nivel.
                unsafe { c_roundtrip_raw(&b, coins, m) }
            }

            fn rust(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida {
                use ml_kem::kem::Decapsulate;
                use ml_kem::{B32, DecapsulationKey, EncapsulationKey, KeyExport, Seed};

                let mut seed = Seed::default();
                seed.copy_from_slice(coins);
                let dk = DecapsulationKey::<$mlk>::from_seed(seed);
                let ek: EncapsulationKey<$mlk> = dk.encapsulation_key().clone();
                let ek_bytes = ek.to_bytes();

                let mut mm = B32::default();
                mm.copy_from_slice(m);
                let (ct, ss_enc) = ek.encapsulate_deterministic(&mm);
                let ss_dec = dk.decapsulate(&ct);

                Salida {
                    pk: ek_bytes.as_slice().to_vec(),
                    ct: ct.as_slice().to_vec(),
                    ss_enc: to_arr(ss_enc.as_slice()),
                    ss_dec: to_arr(ss_dec.as_slice()),
                }
            }

            fn libcrux(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida {
                use libcrux_ml_kem::$lc;
                let kp = $lc::generate_key_pair(*coins);
                let (ct, ss_enc) = $lc::encapsulate(kp.public_key(), *m);
                let ss_dec = $lc::decapsulate(kp.private_key(), &ct);
                Salida {
                    pk: kp.pk().to_vec(),
                    ct: ct.as_slice().to_vec(),
                    ss_enc,
                    ss_dec,
                }
            }

            fn aws(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Salida {
                // SAFETY: NID_KEM, PK y CT son del MISMO nivel.
                unsafe { aws_roundtrip(Self::NID_KEM, Self::PK, Self::CT, coins, m) }
            }
        }
    };
}

nivel_kem!(
    Kem512, "ML-KEM-512", ml_kem::MlKem512, mlkem512, 800, 1632, 768,
    aws_lc_sys::NID_MLKEM512,
    ffi::pqcrystals_kyber512_ref_keypair_derand,
    ffi::pqcrystals_kyber512_ref_enc_derand,
    ffi::pqcrystals_kyber512_ref_dec
);
nivel_kem!(
    Kem768, "ML-KEM-768", ml_kem::MlKem768, mlkem768, 1184, 2400, 1088,
    aws_lc_sys::NID_MLKEM768,
    ffi::pqcrystals_kyber768_ref_keypair_derand,
    ffi::pqcrystals_kyber768_ref_enc_derand,
    ffi::pqcrystals_kyber768_ref_dec
);
nivel_kem!(
    Kem1024, "ML-KEM-1024", ml_kem::MlKem1024, mlkem1024, 1568, 3168, 1568,
    aws_lc_sys::NID_MLKEM1024,
    ffi::pqcrystals_kyber1024_ref_keypair_derand,
    ffi::pqcrystals_kyber1024_ref_enc_derand,
    ffi::pqcrystals_kyber1024_ref_dec
);

/// Veredicto de CUATRO vías: `true` en un campo solo si las cuatro
/// implementaciones (quipu, referencia C, libcrux y AWS-LC) coinciden en esa etapa.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Veredicto {
    pub pk_todas_iguales: bool,
    pub ct_todas_iguales: bool,
    pub ss_enc_todas_iguales: bool,
    pub ss_dec_todas_iguales: bool,
    pub roundtrip_c: bool,
    pub roundtrip_rust: bool,
    pub roundtrip_libcrux: bool,
    pub roundtrip_aws: bool,
}

impl Veredicto {
    #[must_use]
    pub fn acuerdo_total(&self) -> bool {
        self.pk_todas_iguales
            && self.ct_todas_iguales
            && self.ss_enc_todas_iguales
            && self.ss_dec_todas_iguales
            && self.roundtrip_c
            && self.roundtrip_rust
            && self.roundtrip_libcrux
            && self.roundtrip_aws
    }
}

/// Compara las cuatro salidas ya calculadas. La C es la referencia contra la que
/// se miden quipu, libcrux y AWS-LC; cada `&&` clava que ese brazo se compara de
/// verdad.
#[must_use]
pub fn comparar(c: &Salida, r: &Salida, l: &Salida, a: &Salida) -> Veredicto {
    Veredicto {
        pk_todas_iguales: r.pk == c.pk && l.pk == c.pk && a.pk == c.pk,
        ct_todas_iguales: r.ct == c.ct && l.ct == c.ct && a.ct == c.ct,
        ss_enc_todas_iguales: r.ss_enc == c.ss_enc && l.ss_enc == c.ss_enc && a.ss_enc == c.ss_enc,
        ss_dec_todas_iguales: r.ss_dec == c.ss_dec && l.ss_dec == c.ss_dec && a.ss_dec == c.ss_dec,
        roundtrip_c: c.ss_enc == c.ss_dec,
        roundtrip_rust: r.ss_enc == r.ss_dec,
        roundtrip_libcrux: l.ss_enc == l.ss_dec,
        roundtrip_aws: a.ss_enc == a.ss_dec,
    }
}

/// Corre las cuatro implementaciones del nivel `N` con la misma semilla y `m`, y
/// exige acuerdo byte a byte.
#[must_use]
pub fn diferencia<N: NivelKem>(coins: &[u8; COINS_KEYPAIR], m: &[u8; COINS_ENC]) -> Veredicto {
    comparar(
        &N::c(coins, m),
        &N::rust(coins, m),
        &N::libcrux(coins, m),
        &N::aws(coins, m),
    )
}
