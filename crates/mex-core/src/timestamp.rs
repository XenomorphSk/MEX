//! Timestamps UTC canônicos.
//!
//! Todo instante registrado pelo MEX é UTC com precisão fixa de
//! **microssegundos** e uma única representação textual:
//! `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
//!
//! A precisão fixa é uma decisão forense: o timestamp entra no hash da
//! cadeia de auditoria, então precisa sobreviver idêntico a serialização,
//! persistência em SQLite e releitura em outra plataforma. Nanossegundos
//! variam entre sistemas operacionais; microssegundos são portáveis.
//! Como a representação tem largura fixa, a ordenação textual coincide com
//! a ordenação temporal.

use crate::error::{MexError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};

const CANONICAL: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");

/// Instante UTC com precisão de microssegundos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTimestamp(OffsetDateTime);

impl UtcTimestamp {
    /// Instante atual, truncado para microssegundos.
    pub fn now() -> Self {
        Self::from_datetime(OffsetDateTime::now_utc())
    }

    /// Converte qualquer `OffsetDateTime` para UTC e trunca para microssegundos.
    pub fn from_datetime(dt: OffsetDateTime) -> Self {
        let dt = dt.to_offset(UtcOffset::UTC);
        let truncated = dt
            .replace_nanosecond(dt.microsecond() * 1_000)
            .expect("microssegundos * 1000 sempre é um nanossegundo válido");
        Self(truncated)
    }

    /// Converte um `SystemTime` (ex.: mtime de arquivo).
    pub fn from_system_time(t: std::time::SystemTime) -> Self {
        Self::from_datetime(OffsetDateTime::from(t))
    }

    /// Constrói a partir de segundos + microssegundos desde a época Unix
    /// (útil para fixtures determinísticas).
    pub fn from_unix_micros(micros: i64) -> Result<Self> {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(micros) * 1_000)
            .map(Self)
            .map_err(|e| MexError::InvalidInput(format!("timestamp fora do intervalo: {e}")))
    }

    /// Representação canônica (`YYYY-MM-DDTHH:MM:SS.ffffffZ`).
    pub fn to_canonical(&self) -> String {
        self.0
            .format(CANONICAL)
            .expect("formato canônico é sempre representável para anos 0..=9999")
    }

    /// Lê a representação canônica. Qualquer outro formato é rejeitado,
    /// para que valores persistidos não sejam reinterpretados silenciosamente.
    pub fn parse_canonical(s: &str) -> Result<Self> {
        PrimitiveDateTime::parse(s, CANONICAL)
            .map(|p| Self(p.assume_utc()))
            .map_err(|e| MexError::InvalidInput(format!("timestamp não canônico {s:?}: {e}")))
    }

    /// Acesso ao valor subjacente.
    pub fn as_datetime(&self) -> OffsetDateTime {
        self.0
    }
}

impl std::fmt::Display for UtcTimestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_canonical())
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_canonical())
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse_canonical(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn canonical_roundtrip_is_exact() {
        let t = UtcTimestamp::now();
        let s = t.to_canonical();
        assert_eq!(s.len(), 27);
        assert!(s.ends_with('Z'));
        assert_eq!(UtcTimestamp::parse_canonical(&s).unwrap(), t);
    }

    #[test]
    fn non_utc_input_is_normalized_and_truncated() {
        let t = UtcTimestamp::from_datetime(datetime!(2025-03-01 10:00:00.123456789 -03:00));
        assert_eq!(t.to_canonical(), "2025-03-01T13:00:00.123456Z");
    }

    #[test]
    fn rejects_non_canonical_forms() {
        for s in [
            "2025-03-01T13:00:00Z",
            "2025-03-01T13:00:00.123456+00:00",
            "2025-03-01 13:00:00.123456Z",
            "2025-03-01T13:00:00.123456789Z",
        ] {
            assert!(UtcTimestamp::parse_canonical(s).is_err(), "{s}");
        }
    }

    #[test]
    fn text_order_matches_time_order() {
        let a = UtcTimestamp::from_unix_micros(1_000_000).unwrap();
        let b = UtcTimestamp::from_unix_micros(1_000_001).unwrap();
        assert!(a < b);
        assert!(a.to_canonical() < b.to_canonical());
    }
}
