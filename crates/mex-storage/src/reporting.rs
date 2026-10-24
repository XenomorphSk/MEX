//! Registro de relatórios emitidos e de exportações de pacotes.
//!
//! Ambos geram o evento de auditoria `exported` na mesma transação.

use crate::repo::{draft, i64_of};
use crate::{append_audit_in_tx, Result, Storage};
use mex_core::audit::{AuditEvent, AuditKind};
use mex_core::ids::{AcquisitionId, CaseId, ExportId, OperatorId, ReportId};
use mex_core::integrity::Digest256;
use mex_core::model::IntegrityStatus;
use mex_core::timestamp::UtcTimestamp;

/// Formato de relatório.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Relatório técnico estruturado.
    Json,
    /// Relatório técnico legível.
    Html,
}

impl ReportFormat {
    /// Nome estável (também persistido no banco).
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
        }
    }
}

/// Relatório emitido.
#[derive(Debug, Clone)]
pub struct ReportRecord {
    /// Identificador do relatório (o mesmo para as versões JSON e HTML).
    pub report_id: ReportId,
    /// Arquivo emitido (um registro por formato).
    pub file_id: ReportId,
    /// Caso.
    pub case_id: CaseId,
    /// Aquisição.
    pub acquisition_id: AcquisitionId,
    /// Formato.
    pub format: ReportFormat,
    /// Caminho do arquivo emitido.
    pub stored_path: String,
    /// SHA-256 do arquivo emitido.
    pub sha256: Digest256,
    /// Operador.
    pub generated_by: OperatorId,
    /// Quando.
    pub generated_at: UtcTimestamp,
}

/// Exportação de pacote.
#[derive(Debug, Clone)]
pub struct ExportRecord {
    /// Identificador.
    pub id: ExportId,
    /// Caso.
    pub case_id: CaseId,
    /// Aquisição.
    pub acquisition_id: AcquisitionId,
    /// Diretório de destino do pacote copiado.
    pub destination: String,
    /// Hash do manifesto registrado (referência da verificação da cópia).
    pub manifest_sha256: Digest256,
    /// Resultado da verificação da cópia no destino.
    pub status: IntegrityStatus,
    /// Arquivos copiados.
    pub files_copied: u64,
    /// Bytes copiados.
    pub bytes_copied: u64,
    /// Operador.
    pub exported_by: OperatorId,
    /// Quando.
    pub exported_at: UtcTimestamp,
}

impl Storage {
    /// Registra um arquivo de relatório emitido.
    pub async fn record_report(&self, r: &ReportRecord) -> Result<()> {
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO reports (id, case_id, acquisition_id, format, stored_path, sha256,
                 generated_by, generated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(r.file_id.to_string())
        .bind(r.case_id.to_string())
        .bind(r.acquisition_id.to_string())
        .bind(r.format.as_str())
        .bind(&r.stored_path)
        .bind(&r.sha256.hex)
        .bind(r.generated_by.to_string())
        .bind(r.generated_at.to_canonical())
        .execute(&mut *tx)
        .await?;
        let detail = format!(
            "relatório {} ({}) da aquisição {} emitido: {}; sha256 {}",
            r.report_id,
            r.format.as_str(),
            r.acquisition_id,
            r.stored_path,
            r.sha256.hex
        );
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::Exported,
                Some(r.case_id),
                Some(r.generated_by),
                detail,
            ),
            r.generated_at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Registra uma exportação de pacote de evidências.
    pub async fn record_export(&self, e: &ExportRecord) -> Result<()> {
        let mut tx = self.write_tx().await?;
        sqlx::query(
            "INSERT INTO evidence_exports (id, acquisition_id, destination, manifest_sha256,
                 status, files_copied, bytes_copied, exported_by, exported_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(e.id.to_string())
        .bind(e.acquisition_id.to_string())
        .bind(&e.destination)
        .bind(&e.manifest_sha256.hex)
        .bind(e.status.as_str())
        .bind(i64_of(e.files_copied, "files_copied")?)
        .bind(i64_of(e.bytes_copied, "bytes_copied")?)
        .bind(e.exported_by.to_string())
        .bind(e.exported_at.to_canonical())
        .execute(&mut *tx)
        .await?;
        let detail = format!(
            "pacote da aquisição {} exportado para {}: cópia {} ({} arquivos, {} bytes); manifesto sha256 {}",
            e.acquisition_id,
            e.destination,
            e.status.as_str(),
            e.files_copied,
            e.bytes_copied,
            e.manifest_sha256.hex
        );
        append_audit_in_tx(
            &mut tx,
            draft(
                AuditKind::Exported,
                Some(e.case_id),
                Some(e.exported_by),
                detail,
            ),
            e.exported_at,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Eventos da cadeia de auditoria associados ao caso, em ordem.
    pub async fn case_audit_events(&self, case_id: CaseId) -> Result<Vec<AuditEvent>> {
        Ok(self
            .load_audit_chain()
            .await?
            .into_iter()
            .filter(|e| e.case_id == Some(case_id))
            .collect())
    }
}

impl Storage {
    /// Caso ao qual a aquisição pertence.
    pub async fn acquisition_case_id(&self, id: AcquisitionId) -> Result<Option<CaseId>> {
        let v: Option<String> = sqlx::query_scalar("SELECT case_id FROM acquisitions WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(v.map(|s| s.parse()).transpose()?)
    }
}
