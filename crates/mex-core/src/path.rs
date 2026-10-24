//! Caminhos de evidência validados (proteção contra path traversal).
//!
//! Há dois caminhos distintos para cada artefato, e o MEX nunca os mistura:
//!
//! - **`source_path`**: o caminho como reportado pelo dispositivo/backup.
//!   É dado *não confiável*, guardado literalmente como metadado de
//!   proveniência e **nunca** usado para abrir arquivos no host.
//! - **[`EvidencePath`]**: o caminho lógico relativo dentro do pacote de
//!   evidências. Só existe se passar pela validação abaixo, e é o único
//!   caminho que o Evidence Engine converte em caminho do sistema de arquivos.
//!
//! Regras de validação (conservadoras, válidas para Linux e Windows):
//! - relativo, separador `/`, sem componentes vazios, `.` ou `..`;
//! - sem `\`, `:`, NUL, caracteres de controle nem `<>"|?*`;
//! - nenhum componente termina em `.` ou espaço (normalização do Windows);
//! - nenhum nome reservado do Windows (`CON`, `NUL`, `COM1`...);
//! - até 255 bytes por componente e 1024 bytes no total.

use crate::error::{MexError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path::{Path, PathBuf};

const MAX_TOTAL_BYTES: usize = 1024;
const MAX_COMPONENT_BYTES: usize = 255;
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Caminho lógico relativo, validado, dentro de um pacote de evidências.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidencePath(String);

impl EvidencePath {
    /// Valida e constrói um caminho de evidência.
    pub fn new(raw: &str) -> Result<Self> {
        let fail = |reason| {
            Err(MexError::InvalidPath {
                path: raw.chars().take(256).collect(),
                reason,
            })
        };
        if raw.is_empty() {
            return fail("caminho vazio");
        }
        if raw.len() > MAX_TOTAL_BYTES {
            return fail("caminho excede 1024 bytes");
        }
        if raw.starts_with('/') {
            return fail("caminho absoluto não permitido");
        }
        for component in raw.split('/') {
            if let Err(reason) = validate_component(component) {
                return fail(reason);
            }
        }
        Ok(Self(raw.to_owned()))
    }

    /// Forma textual canônica (separador `/`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Componentes do caminho.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// Resolve o caminho sob `root`, componente a componente.
    ///
    /// Seguro por construção: a validação garante que nenhum componente
    /// escapa de `root`. Links simbólicos já existentes sob `root` são
    /// responsabilidade do Evidence Engine (que cria a árvore ele mesmo).
    pub fn resolve_under(&self, root: &Path) -> PathBuf {
        let mut p = root.to_path_buf();
        for c in self.components() {
            p.push(c);
        }
        p
    }
}

fn validate_component(c: &str) -> std::result::Result<(), &'static str> {
    if c.is_empty() {
        return Err("componente vazio (barra dupla ou final)");
    }
    if c == "." || c == ".." {
        return Err("componente '.' ou '..' não permitido");
    }
    if c.len() > MAX_COMPONENT_BYTES {
        return Err("componente excede 255 bytes");
    }
    if c.chars()
        .any(|ch| ch.is_control() || matches!(ch, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err("caractere proibido no componente");
    }
    if c.ends_with('.') || c.ends_with(' ') {
        return Err("componente termina em '.' ou espaço");
    }
    let stem = c.split('.').next().unwrap_or(c).trim_end();
    if WINDOWS_RESERVED
        .iter()
        .any(|r| r.eq_ignore_ascii_case(stem))
    {
        return Err("nome reservado do Windows");
    }
    Ok(())
}

impl std::fmt::Display for EvidencePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for EvidencePath {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EvidencePath {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_paths() {
        for p in [
            "files/sdcard/DCIM/IMG_0001.jpg",
            "device-info.json",
            "backup/com.example.app/db/msgstore.db",
            "fotos/férias 2024/praia.png",
        ] {
            assert!(EvidencePath::new(p).is_ok(), "{p}");
        }
    }

    #[test]
    fn rejects_traversal_and_absolute() {
        for p in [
            "../etc/passwd",
            "a/../../b",
            "a/./b",
            "/etc/passwd",
            "a//b",
            "a/",
            "",
            "..",
        ] {
            assert!(EvidencePath::new(p).is_err(), "{p:?} deveria ser rejeitado");
        }
    }

    #[test]
    fn rejects_windows_hazards() {
        for p in [
            "a\\..\\b",
            "C:/Windows",
            "C:evil",
            "file.txt:ads",
            "dir/CON",
            "dir/nul.txt",
            "dir/Com1.log",
            "trailing.",
            "trailing ",
            "a\0b",
            "a\nb",
            "what?.txt",
        ] {
            assert!(EvidencePath::new(p).is_err(), "{p:?} deveria ser rejeitado");
        }
    }

    #[test]
    fn rejects_oversized() {
        assert!(EvidencePath::new(&"a".repeat(256)).is_err());
        let long = vec!["abcdefgh"; 200].join("/");
        assert!(EvidencePath::new(&long).is_err());
    }

    #[test]
    fn resolve_stays_under_root() {
        let root = Path::new("/evidence/pkg");
        let p = EvidencePath::new("a/b/c.bin").unwrap();
        let resolved = p.resolve_under(root);
        assert!(resolved.starts_with(root));
        assert_eq!(resolved, Path::new("/evidence/pkg/a/b/c.bin"));
    }

    #[test]
    fn deserialization_revalidates() {
        assert!(serde_json::from_str::<EvidencePath>("\"../x\"").is_err());
        assert!(serde_json::from_str::<EvidencePath>("\"ok/x\"").is_ok());
    }
}
