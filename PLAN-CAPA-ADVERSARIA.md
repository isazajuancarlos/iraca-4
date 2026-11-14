<!--
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
SPDX-License-Identifier: MIT
-->
# Plan — capa adversaria de validación/canonicidad en iraca-4

**Estado: CONSTRUIDO 2026-09-25** (`src/adversario.rs`, aprobado por Juan).
**RESULTADO = ASEGURAMIENTO, no hallazgo:** RustCrypto `ml-kem` 0.3 **SÍ** hace el
modulus check de FIPS 203 — leído en el fuente (`pke.rs:168-203`, cita FIPS 203) y
**confirmado por ejecución**: rechaza toda `ek` no-canónica y acepta toda válida en
128 muestras (test `aseguramiento_rustcrypto_rechaza_ek_no_canonica`), con oráculo
del estándar propio y control positivo (D30/D33). No hay bug que divulgar en esta
superficie; el entregable es un **writeup de aseguramiento** (contenido de
promoción). La caza de un hallazgo real se mueve a superficies más ricas (ML-DSA:
no-canonicidad/maleabilidad de hint, iraca-2).

## 1. Objetivo

Detectar **huecos de conformidad** en implementaciones ML-KEM: ¿rechaza la
implementación las entradas malformadas / no-canónicas que **FIPS 203 exige
rechazar**? Blanco inicial: **`ml-kem` de RustCrypto** (el crate que quipu usa por
dentro y que **NO está auditado**; lo consume medio ecosistema Rust).

Método: **diferencial adversario** — la MISMA entrada inválida a los dos lados
(crate Rust vs referencia pq-crystals C, ya vendorizada en iraca-4) + **vectores
ACVP negativos** de NIST; comparar **aceptar/rechazar**.

## 2. Por qué este objetivo (la precisión)

- FIPS 203 EXIGE el **"modulus check"** (rechazar `ek` no-canónica:
  `ByteEncode12(ByteDecode12(ek)) == ek`) y la validación de ciphertext.
- Está **documentado que algunas implementaciones lo omiten** ("not implemented
  yet; ACVP vectors available but not wired into tests").
- El diferencial de **I/O lo caza** (a diferencia del timing/KyberSlash, que exige
  medición y ya está parcheado desde dic-2023 → fuera de alcance a propósito).
- Segundo oráculo posible: **libcrux/Cryspen** (ML-KEM en Rust formalmente
  verificado) como control adicional.

## 3. Alcance de la PRIMERA pasada (acotado)

- Algoritmo: **ML-KEM-768** (el que iraca-4 ya cubre).
- Superficie de entrada inválida:
  1. **`ek` no-canónica** (coeficiente ≥ q en la codificación de 12 bits) → ¿la
     rechaza encaps? (modulus check).
  2. **ciphertext malformado** (longitud incorrecta, relleno) → ¿decaps rechaza o
     produce basura en silencio?
  3. **`dk`/seed fuera de rango o longitud** → ¿rechaza?
- Oráculos: (a) pq-crystals C; (b) vectores **ACVP negativos** NIST; (c) opcional
  libcrux verificado.

## 4. Qué es HALLAZGO vs ASEGURAMIENTO vs FALSO POSITIVO

- **HALLAZGO** (reportable): RustCrypto **acepta / no rechaza / produce salida en
  vez de error** ante una entrada que la referencia y ACVP marcan inválida. Exige
  **PoC mínimo determinista** antes de tocar al mantenedor.
- **ASEGURAMIENTO**: RustCrypto rechaza todo lo que debe → writeup de conformidad
  (promoción, sin ventana de divulgación).
- **FALSO POSITIVO a descartar** (D33): ambos se comportan igual; o la "invalidez"
  **no la exige el estándar**. La aguja se valida contra el ARTEFACTO —el texto de
  FIPS 203 / los vectores ACVP—, **no contra mi intuición** (D30).

## 5. Diseño técnico (a construir, con banco D33)

- **Generador de entradas adversarias**: mutadores dirigidos (coef ≥ q; byte de
  longitud; truncado; relleno; bit-flip en zonas de validación).
- **Comparador** aceptar/rechazar entre crate y referencia, clasificado por causa.
- **Pareja D33 por cada mutador**: un caso que DEBE rechazarse (rojo real, inválido
  de verdad — no roto por el arnés) y uno válido que DEBE pasar (verde).
- **Aguja validada contra el artefacto**: usar vectores **ACVP negativos** como
  entrada inválida conocida; **positivo de control** (D30): la referencia rechaza
  el ACVP-negativo (prueba que el camino de rechazo se ejecutó) y acepta el válido.

## 6. Riesgos y honestidad (calibrar expectativa)

- **Lo maduro suele salir seco** (lección nexus): es probable que RustCrypto ya
  haga los checks → resultado = **aseguramiento** (igual sirve como promoción).
- **ACVP**: hay que bajar y parsear los vectores del ACVP-server de NIST
  (dependencia de datos PÚBLICOS externos).
- **No cubre timing** (otra familia; deliberadamente fuera).
- Todo hallazgo → **PoC determinista mínimo** antes de divulgación responsable.

## 7. Pipeline de salida (acordado con Juan)

iraca (a DEMANDA, como nexus+razonador) → **razonador (Claude) verifica y
reproduce** → **informe privado al mantenedor** (RustCrypto) → **publicación en el
medio** (pqc-forum / GitHub) **cuando esté aceptado/arreglado**. Si es
aseguramiento → writeup abierto con visto bueno de Juan. Publicar es irreversible →
compuerta humana siempre.

## 8. Entregable de la primera pasada

Un **veredicto**: hallazgo (con PoC + borrador de reporte responsable) o
aseguramiento (con writeup listo para aprobación), más el **banco D33 verde**.

## 9. Lo que NO hace este plan

- No construye variante de **timing/side-channel** (otra disciplina; leads ya
  ubicados por mindalá: `phayes/sidefuzz`, `eshard/scared`, ChipWhisperer).
- No toca quipu (iraca sigue sin depender de quipu; prueba los CRATES que quipu
  usa, no quipu).
- No publica nada automáticamente.
