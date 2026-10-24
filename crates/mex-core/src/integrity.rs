//! Integridade criptográfica de artefatos.
//!
//! Fornece um hasher SHA-256 incremental (streaming), adequado para
//! artefatos grandes que não cabem em memória, e utilidades de verificação.

use crate::error::{MexError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;

/// Tamanho do bloco de leitura usado em [`hash_reader`].
pub const HASH_BLOCK_SIZE: usize = 1024 * 1024;

/// Algoritmo de digest suportado. Fixado em SHA-256 no MVP, mas modelado
/// como enum para futura evolução (ex.: SHA-512, BLAKE3) sem quebra de dados.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DigestAlg {
    /// SHA-256.
    #[serde(rename = "sha-256")]
    Sha256,
}

impl DigestAlg {
    /// Nome canônico do algoritmo (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            DigestAlg::Sha256 => "sha-256",
        }
    }
}

/// Digest calculado: algoritmo + valor hexadecimal minúsculo.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest256 {
    /// Algoritmo usado.
    pub alg: DigestAlg,
    /// Valor em hexadecimal minúsculo (64 chars para SHA-256).
    pub hex: String,
}

impl Digest256 {
    /// Constrói a partir de um hex SHA-256 externo, validando formato.
    /// Aceita maiúsculas e normaliza para minúsculas.
    pub fn sha256_from_hex(hex_value: &str) -> Result<Self> {
        let hex_value = hex_value.trim().to_ascii_lowercase();
        if hex_value.len() != 64 || !hex_value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(MexError::InvalidInput(format!(
                "digest SHA-256 deve ter 64 dígitos hex: {hex_value:?}"
            )));
        }
        Ok(Self {
            alg: DigestAlg::Sha256,
            hex: hex_value,
        })
    }

    /// Compara com um valor esperado; erro se divergente.
    pub fn verify_eq(&self, expected: &Digest256) -> Result<()> {
        if self == expected {
            Ok(())
        } else {
            Err(MexError::IntegrityMismatch {
                expected: expected.hex.clone(),
                actual: self.hex.clone(),
            })
        }
    }
}

/// Hasher incremental. Alimente com `update` e finalize com `finalize`.
#[derive(Clone)]
pub struct StreamHasher {
    inner: Sha256,
    bytes: u64,
}

impl Default for StreamHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamHasher {
    /// Cria um hasher SHA-256 vazio.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
            bytes: 0,
        }
    }

    /// Acrescenta um bloco de dados.
    pub fn update(&mut self, chunk: &[u8]) {
        self.inner.update(chunk);
        self.bytes += chunk.len() as u64;
    }

    /// Total de bytes processados até agora.
    pub fn bytes_hashed(&self) -> u64 {
        self.bytes
    }

    /// Finaliza e retorna o digest.
    pub fn finalize(self) -> Digest256 {
        Digest256 {
            alg: DigestAlg::Sha256,
            hex: hex::encode(self.inner.finalize()),
        }
    }
}

/// Calcula o SHA-256 de um buffer completo em memória.
pub fn sha256_hex(data: &[u8]) -> Digest256 {
    let mut h = StreamHasher::new();
    h.update(data);
    h.finalize()
}

/// Calcula o SHA-256 de um leitor em blocos de [`HASH_BLOCK_SIZE`], com
/// memória constante. Devolve o digest e o total de bytes lidos.
pub fn hash_reader<R: Read>(mut reader: R) -> std::io::Result<(Digest256, u64)> {
    let mut h = StreamHasher::new();
    let mut buf = vec![0u8; HASH_BLOCK_SIZE];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let n = h.bytes_hashed();
    Ok((h.finalize(), n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hex_validates_and_normalizes() {
        let upper = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        let d = Digest256::sha256_from_hex(upper).unwrap();
        assert_eq!(d, sha256_hex(b"abc"));
        assert!(Digest256::sha256_from_hex("abc").is_err());
        assert!(Digest256::sha256_from_hex(&"g".repeat(64)).is_err());
    }

    #[test]
    fn verify_eq_reports_mismatch() {
        let a = sha256_hex(b"a");
        let b = sha256_hex(b"b");
        assert!(a.verify_eq(&a.clone()).is_ok());
        assert!(matches!(
            a.verify_eq(&b),
            Err(MexError::IntegrityMismatch { .. })
        ));
    }
}
