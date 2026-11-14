// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: MIT
//! Capa ADVERSARIA de validación/canonicidad (ML-KEM-768).
//!
//! Pregunta: ¿la implementación **rechaza** las claves de encapsulación (`ek`)
//! NO-CANÓNICAS, como EXIGE FIPS 203 (§7.2, "modulus check":
//! `ByteEncode12(ByteDecode12(ek)) == ek`)? Una `ek` con algún coeficiente ≥ q
//! (=3329) NO es canónica y debe rechazarse.
//!
//! El oráculo de "canónica o no" es el ESTÁNDAR (lo calculamos aquí,
//! [`ek_es_canonica`]), NO la implementación bajo prueba ni la referencia C —
//! porque la referencia histórica de kyber podía NO hacer este check (es una
//! adición de FIPS 203). Así la aguja se valida contra el ARTEFACTO (el texto de
//! FIPS 203), no contra otra implementación (D33/D30).
//!
//! Resultado esperado en RustCrypto `ml-kem` 0.3 (leído en `pke.rs:168-203`, que
//! cita FIPS 203): DEBE rechazar → esto es una verificación de ASEGURAMIENTO, no
//! la caza de un bug. Si alguna vez una implementación ACEPTA una `ek`
//! no-canónica, eso es un hallazgo de conformidad reportable.

use ml_kem::{DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};

/// El módulo primo de Kyber/ML-KEM.
pub const Q: u16 = 3329;
/// Bytes de la parte `t_hat` de la `ek` en ML-KEM-768 (k=3): 384·k = 1152.
pub const THAT_BYTES: usize = 1152;

/// ¿Es canónica la `ek`? (todos los coeficientes de 12 bits de `t_hat` < q).
/// Este es el oráculo del ESTÁNDAR; `ek` debe medir 1184 bytes (1152 + 32 de rho).
#[must_use]
pub fn ek_es_canonica(ek: &[u8]) -> bool {
    if ek.len() < THAT_BYTES {
        return false;
    }
    // 12 bits por coeficiente: cada 3 bytes → 2 coeficientes (THAT_BYTES es múltiplo de 3).
    let mut i = 0;
    while i + 2 < THAT_BYTES {
        let b0 = u16::from(ek[i]);
        let b1 = u16::from(ek[i + 1]);
        let b2 = u16::from(ek[i + 2]);
        let c0 = b0 | ((b1 & 0x0F) << 8);
        let c1 = (b1 >> 4) | (b2 << 4);
        if c0 >= Q || c1 >= Q {
            return false;
        }
        i += 3;
    }
    true
}

type Ek = EncapsulationKey<MlKem768>;
type EkBytes = <Ek as ml_kem::KeySizeUser>::KeySize;

/// Los bytes serializados de una `ek` (el tipo `Key` de RustCrypto), para poder
/// mutarlos y re-alimentarlos al validador del crate.
pub type EkKey = ml_kem::array::Array<u8, EkBytes>;

/// Genera una `ek` VÁLIDA (canónica) de una semilla de 64 bytes.
#[must_use]
pub fn ek_valida(coins: &[u8; 64]) -> EkKey {
    let mut seed = ml_kem::Seed::default();
    seed.copy_from_slice(coins);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
    dk.encapsulation_key().to_bytes()
}

/// Convierte una `ek` canónica en NO-canónica: fuerza el primer coeficiente de 12
/// bits a 4095 (≥ q). Devuelve la `ek` mutada.
#[must_use]
pub fn ek_no_canonica(mut ek: EkKey) -> EkKey {
    // coef0 = ek[0] | ((ek[1] & 0x0F) << 8). Para hacerlo 0xFFF: ek[0]=0xFF, ek[1]|=0x0F.
    ek[0] = 0xFF;
    ek[1] |= 0x0F;
    ek
}

/// ¿El crate RustCrypto ACEPTA esta `ek`? (`new` devuelve `Ok`).
#[must_use]
pub fn rustcrypto_acepta(ek: &EkKey) -> bool {
    Ek::new(ek).is_ok()
}

/// Veredicto de una corrida del verificador de conformidad.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reporte {
    /// Muestras probadas.
    pub probadas: usize,
    /// Canónicas ACEPTADAS (debe = probadas): ninguna válida se rechaza de más.
    pub validas_aceptadas: usize,
    /// No-canónicas RECHAZADAS (debe = probadas): el modulus check funciona.
    pub no_canonicas_rechazadas: usize,
    /// HALLAZGO: no-canónicas que el crate ACEPTÓ (debe = 0). > 0 = hueco de
    /// conformidad reportable.
    pub no_canonicas_aceptadas: usize,
}

impl Reporte {
    /// Conformidad total: acepta todas las válidas y rechaza todas las no-canónicas.
    #[must_use]
    pub fn conforme(&self) -> bool {
        self.validas_aceptadas == self.probadas
            && self.no_canonicas_rechazadas == self.probadas
            && self.no_canonicas_aceptadas == 0
    }
}

/// Corre el verificador sobre `muestras` semillas: por cada una prueba la `ek`
/// canónica (debe aceptarse) y su mutante no-canónica (debe rechazarse).
#[must_use]
pub fn verificar_modulus_check(semillas: &[[u8; 64]]) -> Reporte {
    let mut r = Reporte::default();
    for coins in semillas {
        r.probadas += 1;

        let valida = ek_valida(coins);
        debug_assert!(ek_es_canonica(&valida), "keygen produjo ek no-canónica");
        if rustcrypto_acepta(&valida) {
            r.validas_aceptadas += 1;
        }

        let mala = ek_no_canonica(valida);
        debug_assert!(!ek_es_canonica(&mala), "el mutante seguía siendo canónico");
        if rustcrypto_acepta(&mala) {
            r.no_canonicas_aceptadas += 1; // HALLAZGO potencial
        } else {
            r.no_canonicas_rechazadas += 1;
        }
    }
    r
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn sm64(estado: &mut u64) -> u64 {
        *estado = estado.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *estado;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn semilla(estado: &mut u64) -> [u8; 64] {
        let mut s = [0u8; 64];
        for t in s.chunks_mut(8) {
            t.copy_from_slice(&sm64(estado).to_le_bytes()[..t.len()]);
        }
        s
    }

    #[test]
    fn el_oraculo_de_canonicidad_discrimina() {
        // D33: el oráculo del estándar debe ver canónica la real y no-canónica el
        // mutante. Si no discrimina, todo lo demás es ruido.
        let v = ek_valida(&[7u8; 64]);
        assert!(ek_es_canonica(&v), "una ek de keygen debe ser canónica");
        let m = ek_no_canonica(v);
        assert!(!ek_es_canonica(&m), "el mutante debe ser no-canónico");
    }

    #[test]
    fn aseguramiento_rustcrypto_rechaza_ek_no_canonica() {
        // El resultado esperado (pke.rs:168-203 implementa el modulus check):
        // acepta las válidas, RECHAZA las no-canónicas. Es ASEGURAMIENTO.
        let mut e = 0xA5A5_1234_DEAD_0001u64;
        let semillas: Vec<[u8; 64]> = (0..128).map(|_| semilla(&mut e)).collect();
        let r = verificar_modulus_check(&semillas);
        assert_eq!(r.probadas, 128);
        assert!(
            r.conforme(),
            "RustCrypto ml-kem debía aceptar toda ek válida y rechazar toda no-canónica; \
             si no_canonicas_aceptadas>0 es un HALLAZGO, revisar: {r:?}"
        );
    }

    #[test]
    fn control_positivo_el_validador_de_verdad_puede_rechazar() {
        // D30: probar que el camino de RECHAZO del crate se ejecuta de verdad —
        // una ek de basura (todo 0xFF) debe ser rechazada. Si esto pasara, el
        // "rechaza no-canónicas" de arriba no probaría nada.
        let basura = ek_no_canonica(ek_valida(&[9u8; 64]));
        assert!(!rustcrypto_acepta(&basura), "el crate aceptó una ek no-canónica evidente");
        // Y una válida SÍ pasa (no es que rechace todo).
        assert!(rustcrypto_acepta(&ek_valida(&[9u8; 64])), "el crate rechazó una ek válida");
    }
}
