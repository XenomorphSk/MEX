//! Verificação posterior de integridade de um pacote de evidências.
//!
//! Função síncrona e somente leitura (use `spawn_blocking` em contexto
//! assíncrono). Nunca segue links simbólicos e nunca altera o pacote.
//!
//! Classificação:
//! - `Incomplete`: falta `manifest.json` ou o selo `manifest.sha256`;
//! - `Compromised`: qualquer divergência;
//! - `Intact`: selo confere, manifesto coerente, todos os artefatos com
//!   tamanho e SHA-256 corretos, `SHA256SUMS` coerente, nenhum arquivo extra.

use crate::manifest::{parse_seal, Manifest};
use crate::{ARTIFACTS_DIR, MANIFEST_DIGEST_FILE, MANIFEST_FILE, STAGING_DIR, SUMS_FILE};
use mex_core::ids::AcquisitionId;
use mex_core::integrity::{hash_reader, sha256_hex, Digest256};
use mex_core::model::IntegrityStatus;
use mex_core::timestamp::UtcTimestamp;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Tamanho máximo aceito para `manifest.json`.
pub const MAX_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DEPTH: usize = 256;

/// Tipo de divergência encontrada.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum FindingKind {
    /// `manifest.json` ausente.
    ManifestMissing,
    /// `manifest.sha256` ausente.
    SealMissing,
    /// Selo em formato inválido.
    SealMalformed,
    /// Hash do manifesto difere do selo.
    SealMismatch {
        /// Valor no selo.
        sealed: String,
        /// Valor calculado.
        actual: String,
    },
    /// Hash do manifesto difere do valor registrado externamente (banco/auditoria).
    RegisteredHashMismatch {
        /// Valor registrado.
        registered: String,
        /// Valor calculado.
        actual: String,
    },
    /// Manifesto ilegível ou inválido.
    ManifestInvalid {
        /// Detalhe.
        detail: String,
    },
    /// Manifesto internamente incoerente.
    ManifestInconsistent {
        /// Detalhe.
        detail: String,
    },
    /// `SHA256SUMS` ausente ou divergente do manifesto.
    SumsMismatch,
    /// Artefato completo ausente.
    ArtifactMissing,
    /// O caminho existe mas não é arquivo regular (ex.: link simbólico).
    NotRegularFile,
    /// Tamanho divergente.
    SizeMismatch {
        /// Esperado.
        expected: u64,
        /// Encontrado.
        actual: u64,
    },
    /// Hash divergente.
    HashMismatch {
        /// Esperado.
        expected: String,
        /// Calculado.
        actual: String,
    },
    /// Arquivo presente para um artefato registrado como falho.
    FailedArtifactPresent,
    /// Arquivo ou link em `artifacts/` que não consta do manifesto.
    UnexpectedEntry,
    /// Área temporária ainda presente.
    StagingLeftover,
    /// Erro de leitura.
    ReadError {
        /// Detalhe.
        detail: String,
    },
}

/// Divergência, com o objeto a que se refere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Caminho relativo ao pacote, ou nome do arquivo de controle.
    pub subject: String,
    /// Tipo.
    #[serde(flatten)]
    pub kind: FindingKind,
}

/// Resultado da verificação.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    /// Pacote verificado.
    pub package_dir: PathBuf,
    /// Classificação.
    pub status: IntegrityStatus,
    /// Aquisição, se o manifesto pôde ser lido.
    pub acquisition_id: Option<AcquisitionId>,
    /// Hash calculado de `manifest.json`, se presente.
    pub manifest_sha256: Option<Digest256>,
    /// Artefatos completos conferidos.
    pub artifacts_checked: usize,
    /// Bytes relidos e conferidos.
    pub bytes_verified: u64,
    /// Divergências.
    pub findings: Vec<Finding>,
    /// Quando.
    pub verified_at: UtcTimestamp,
}

/// Verifica o pacote em `package_dir`.
///
/// `registered_manifest_sha256` é o hash registrado no banco/cadeia de
/// auditoria no momento da aquisição. Quando informado, protege contra quem
/// reescreve manifesto **e** selo.
pub fn verify_package(
    package_dir: &Path,
    registered_manifest_sha256: Option<&Digest256>,
) -> VerificationReport {
    let mut v = Verifier {
        root: package_dir.to_path_buf(),
        findings: Vec::new(),
        artifacts_checked: 0,
        bytes_verified: 0,
    };
    let (manifest, digest, incomplete) = v.check_manifest(registered_manifest_sha256);
    if let Some(m) = &manifest {
        v.check_artifacts(m);
        v.check_sums(m);
    }
    if fs::symlink_metadata(package_dir.join(STAGING_DIR)).is_ok() {
        v.find(STAGING_DIR, FindingKind::StagingLeftover);
    }
    let status = if incomplete {
        IntegrityStatus::Incomplete
    } else if v.findings.is_empty() {
        IntegrityStatus::Intact
    } else {
        IntegrityStatus::Compromised
    };
    VerificationReport {
        package_dir: package_dir.to_path_buf(),
        status,
        acquisition_id: manifest.map(|m| m.acquisition_id),
        manifest_sha256: digest,
        artifacts_checked: v.artifacts_checked,
        bytes_verified: v.bytes_verified,
        findings: v.findings,
        verified_at: UtcTimestamp::now(),
    }
}

/// Abre para leitura sem seguir link simbólico no último componente
/// (`O_NOFOLLOW` no Linux).
fn open_nofollow(p: &Path) -> std::io::Result<fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(p)
    }
    #[cfg(not(target_os = "linux"))]
    {
        fs::File::open(p)
    }
}

/// `ELOOP`: a abertura encontrou um link simbólico e recusou segui-lo.
fn is_symlink_refusal(e: &std::io::Error) -> bool {
    #[cfg(target_os = "linux")]
    {
        e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = e;
        false
    }
}

struct Verifier {
    root: PathBuf,
    findings: Vec<Finding>,
    artifacts_checked: usize,
    bytes_verified: u64,
}

impl Verifier {
    fn find(&mut self, subject: impl Into<String>, kind: FindingKind) {
        self.findings.push(Finding {
            subject: subject.into(),
            kind,
        });
    }

    /// Lê arquivo regular pequeno, sem seguir links.
    fn read_control_file(&mut self, name: &str, max: u64) -> Option<Vec<u8>> {
        let p = self.root.join(name);
        match fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.find(
                    name,
                    FindingKind::ReadError {
                        detail: e.to_string(),
                    },
                );
                None
            }
            Ok(m) if !m.file_type().is_file() => {
                self.find(name, FindingKind::NotRegularFile);
                None
            }
            Ok(m) if m.len() > max => {
                self.find(
                    name,
                    FindingKind::ManifestInvalid {
                        detail: format!("excede {max} bytes"),
                    },
                );
                None
            }
            Ok(_) => {
                let mut buf = Vec::new();
                match open_nofollow(&p).and_then(|f| f.take(max).read_to_end(&mut buf)) {
                    Ok(_) => Some(buf),
                    Err(e) => {
                        self.find(
                            name,
                            FindingKind::ReadError {
                                detail: e.to_string(),
                            },
                        );
                        None
                    }
                }
            }
        }
    }

    fn check_manifest(
        &mut self,
        registered: Option<&Digest256>,
    ) -> (Option<Manifest>, Option<Digest256>, bool) {
        let manifest_present = fs::symlink_metadata(self.root.join(MANIFEST_FILE)).is_ok();
        let bytes = self.read_control_file(MANIFEST_FILE, MAX_MANIFEST_BYTES);
        let seal_present = fs::symlink_metadata(self.root.join(MANIFEST_DIGEST_FILE)).is_ok();
        let seal = self.read_control_file(MANIFEST_DIGEST_FILE, 1024);

        if !manifest_present {
            self.find(MANIFEST_FILE, FindingKind::ManifestMissing);
        }
        if !seal_present {
            self.find(MANIFEST_DIGEST_FILE, FindingKind::SealMissing);
        }
        let incomplete = !manifest_present || !seal_present;
        let Some(bytes) = bytes else {
            return (None, None, incomplete);
        };
        let digest = sha256_hex(&bytes);

        if let Some(seal) = seal {
            match std::str::from_utf8(&seal).ok().and_then(parse_seal) {
                None => self.find(MANIFEST_DIGEST_FILE, FindingKind::SealMalformed),
                Some(sealed) if sealed != digest => self.find(
                    MANIFEST_DIGEST_FILE,
                    FindingKind::SealMismatch {
                        sealed: sealed.hex,
                        actual: digest.hex.clone(),
                    },
                ),
                Some(_) => {}
            }
        }
        if let Some(reg) = registered {
            if reg != &digest {
                self.find(
                    MANIFEST_FILE,
                    FindingKind::RegisteredHashMismatch {
                        registered: reg.hex.clone(),
                        actual: digest.hex.clone(),
                    },
                );
            }
        }

        let manifest = match serde_json::from_slice::<Manifest>(&bytes) {
            Ok(m) => m,
            Err(e) => {
                self.find(
                    MANIFEST_FILE,
                    FindingKind::ManifestInvalid {
                        detail: e.to_string(),
                    },
                );
                return (None, Some(digest), incomplete);
            }
        };
        for detail in manifest.consistency_problems() {
            self.find(MANIFEST_FILE, FindingKind::ManifestInconsistent { detail });
        }
        (Some(manifest), Some(digest), incomplete)
    }

    fn check_artifacts(&mut self, m: &Manifest) {
        let base = self.root.join(ARTIFACTS_DIR);
        let mut expected = BTreeSet::new();
        for a in &m.artifacts {
            let rel = format!("{ARTIFACTS_DIR}/{}", a.stored_path);
            let path = a.stored_path.resolve_under(&base);
            let meta = fs::symlink_metadata(&path);
            match a.digest() {
                None => {
                    // Falho: não pode existir arquivo publicado.
                    if meta.is_ok() && !expected.contains(a.stored_path.as_str()) {
                        self.find(rel, FindingKind::FailedArtifactPresent);
                    }
                }
                Some(digest) => {
                    expected.insert(a.stored_path.as_str().to_owned());
                    self.artifacts_checked += 1;
                    let m = match meta {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            self.find(rel, FindingKind::ArtifactMissing);
                            continue;
                        }
                        Err(e) => {
                            self.find(
                                rel,
                                FindingKind::ReadError {
                                    detail: e.to_string(),
                                },
                            );
                            continue;
                        }
                        Ok(m) => m,
                    };
                    if !m.file_type().is_file() {
                        self.find(rel, FindingKind::NotRegularFile);
                        continue;
                    }
                    if m.len() != a.size_bytes {
                        self.find(
                            rel,
                            FindingKind::SizeMismatch {
                                expected: a.size_bytes,
                                actual: m.len(),
                            },
                        );
                        continue;
                    }
                    // Tipo e tamanho reconferidos no descritor que será lido:
                    // uma troca entre o `lstat` acima e a abertura não passa.
                    let file = match open_nofollow(&path) {
                        Ok(f) => f,
                        Err(e) if is_symlink_refusal(&e) => {
                            self.find(rel, FindingKind::NotRegularFile);
                            continue;
                        }
                        Err(e) => {
                            self.find(
                                rel,
                                FindingKind::ReadError {
                                    detail: e.to_string(),
                                },
                            );
                            continue;
                        }
                    };
                    match file.metadata() {
                        Ok(fm) if !fm.is_file() => {
                            self.find(rel, FindingKind::NotRegularFile);
                            continue;
                        }
                        Ok(fm) if fm.len() != a.size_bytes => {
                            self.find(
                                rel,
                                FindingKind::SizeMismatch {
                                    expected: a.size_bytes,
                                    actual: fm.len(),
                                },
                            );
                            continue;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            self.find(
                                rel,
                                FindingKind::ReadError {
                                    detail: e.to_string(),
                                },
                            );
                            continue;
                        }
                    }
                    match hash_reader(file) {
                        Err(e) => self.find(
                            rel,
                            FindingKind::ReadError {
                                detail: e.to_string(),
                            },
                        ),
                        Ok((actual, n)) => {
                            self.bytes_verified += n;
                            if &actual != digest {
                                self.find(
                                    rel,
                                    FindingKind::HashMismatch {
                                        expected: digest.hex.clone(),
                                        actual: actual.hex,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
        // Entradas presentes em disco e ausentes do manifesto.
        let mut found = Vec::new();
        self.walk(&base, String::new(), 0, &mut found);
        for rel in found {
            if !expected.contains(&rel) {
                self.find(
                    format!("{ARTIFACTS_DIR}/{rel}"),
                    FindingKind::UnexpectedEntry,
                );
            }
        }
    }

    /// Lista arquivos (e qualquer não-diretório) sob `dir`, sem seguir links.
    fn walk(&mut self, dir: &Path, prefix: String, depth: usize, out: &mut Vec<String>) {
        if depth > MAX_DEPTH {
            self.find(
                prefix,
                FindingKind::ReadError {
                    detail: "profundidade excessiva".into(),
                },
            );
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => {
                self.find(
                    format!("{ARTIFACTS_DIR}/{prefix}"),
                    FindingKind::ReadError {
                        detail: e.to_string(),
                    },
                );
                return;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            match entry.file_type() {
                Ok(t) if t.is_dir() => self.walk(&entry.path(), rel, depth + 1, out),
                _ => out.push(rel),
            }
        }
    }

    fn check_sums(&mut self, m: &Manifest) {
        match self.read_control_file(SUMS_FILE, MAX_MANIFEST_BYTES) {
            Some(bytes) if bytes == m.sha256sums().as_bytes() => {}
            _ => self.find(SUMS_FILE, FindingKind::SumsMismatch),
        }
    }
}
