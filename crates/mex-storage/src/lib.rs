//! # mex-storage
//!
//! Persistência SQLite do BlackBit MEX via SQLx.
//!
//! - Migrations versionadas em `migrations/` (raiz do workspace), embutidas
//!   no binário em tempo de compilação.
//! - Integridade referencial (`foreign_keys`) ativada em toda conexão.
//! - Regras forenses críticas reforçadas no próprio schema (triggers):
//!   auditoria append-only e sequencial, artefato `complete` só com hash,
//!   registros finalizados imutáveis.
//!
//! Toda operação de repositório que altera dados registra o evento de
//! auditoria correspondente **na mesma transação** (ver [`repo`]).

use mex_core::audit::{verify_chain, AuditDraft, AuditEvent};
use mex_core::timestamp::UtcTimestamp;
use mex_core::MexError;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
    SqliteSynchronous,
};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

pub mod query;
pub mod recovery;
pub mod repo;
pub mod reporting;

/// Versão deste módulo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Versão mais recente do schema embutida neste build.
pub fn schema_version() -> i64 {
    MIGRATOR.iter().map(|m| m.version).max().unwrap_or(0)
}

/// Migrations do workspace, embutidas no binário.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// Erros da camada de persistência.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Erro do SQLite/SQLx (inclui violações de CHECK, FK e triggers).
    #[error("erro de banco de dados: {0}")]
    Database(#[from] sqlx::Error),
    /// Falha ao aplicar migrations.
    #[error("erro de migration: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    /// Erro de domínio (inclui dado persistido que não passa na validação).
    #[error(transparent)]
    Domain(#[from] MexError),
}

/// Resultado da camada de persistência.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Banco de dados do MEX.
#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    /// Abre (ou cria) o banco em `path` e aplica as migrations pendentes.
    ///
    /// Usa journal WAL e `synchronous = FULL`: um commit retornado sobrevive
    /// a queda de energia, ao custo de desempenho de escrita.
    pub async fn open(path: &Path) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await?;
        Self::init(pool).await
    }

    /// Banco em memória (testes). Usa uma única conexão permanente, pois cada
    /// conexão SQLite em memória é um banco distinto.
    pub async fn open_in_memory() -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(opts)
            .await?;
        Self::init(pool).await
    }

    async fn init(pool: SqlitePool) -> Result<Self> {
        MIGRATOR.run(&pool).await?;
        tracing::info!(
            migrations = MIGRATOR.iter().count(),
            "schema do MEX atualizado"
        );
        Ok(Self { pool })
    }

    /// Pool subjacente (para repositórios de outros crates e testes).
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Fecha o pool, aguardando as conexões.
    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Acrescenta um evento à cadeia de auditoria, encadeando-o ao último.
    ///
    /// Leitura do último evento e inserção ocorrem na mesma transação. Em
    /// caso de escrita concorrente, o trigger `audit_events_sequential` e a
    /// chave primária `seq` fazem uma das inserções falhar — a cadeia nunca
    /// bifurca; o chamador pode repetir a operação.
    pub async fn append_audit_event(
        &self,
        draft: AuditDraft,
        at: UtcTimestamp,
    ) -> Result<AuditEvent> {
        let mut tx = self.write_tx().await?;
        let ev = append_audit_in_tx(&mut tx, draft, at).await?;
        tx.commit().await?;
        Ok(ev)
    }

    /// Abre uma transação de escrita (`BEGIN IMMEDIATE`): adquire o lock de
    /// escrita no início, serializando escritores concorrentes em vez de
    /// falhar no meio da transação.
    pub(crate) async fn write_tx(&self) -> Result<Transaction<'static, Sqlite>> {
        Ok(self.pool.begin_with("BEGIN IMMEDIATE").await?)
    }

    /// Carrega a cadeia de auditoria completa, em ordem.
    pub async fn load_audit_chain(&self) -> Result<Vec<AuditEvent>> {
        sqlx::query(AUDIT_SELECT_ALL)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(audit_from_row)
            .collect()
    }

    /// Carrega e verifica a cadeia; devolve o número de eventos verificados.
    pub async fn verify_audit_chain(&self) -> Result<usize> {
        let chain = self.load_audit_chain().await?;
        verify_chain(&chain)?;
        Ok(chain.len())
    }
}

const AUDIT_SELECT_LAST: &str =
    "SELECT seq, id, case_id, operator_id, kind, detail, at, prev_hash, entry_hash
     FROM audit_events ORDER BY seq DESC LIMIT 1";
const AUDIT_SELECT_ALL: &str =
    "SELECT seq, id, case_id, operator_id, kind, detail, at, prev_hash, entry_hash
     FROM audit_events ORDER BY seq ASC";

/// Encadeia e insere um evento de auditoria **dentro** da transação dada.
///
/// Usado pelos repositórios para que o dado e o seu evento de auditoria
/// sejam gravados atomicamente: ou ambos, ou nenhum.
pub(crate) async fn append_audit_in_tx(
    conn: &mut SqliteConnection,
    draft: AuditDraft,
    at: UtcTimestamp,
) -> Result<AuditEvent> {
    let last = sqlx::query(AUDIT_SELECT_LAST)
        .fetch_optional(&mut *conn)
        .await?
        .map(|r| audit_from_row(&r))
        .transpose()?;
    let ev = AuditEvent::append(last.as_ref(), draft, at)?;
    sqlx::query(
        "INSERT INTO audit_events
             (seq, id, case_id, operator_id, kind, detail, at, prev_hash, entry_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(seq_to_i64(ev.seq)?)
    .bind(ev.id.to_string())
    .bind(ev.case_id.map(|c| c.to_string()))
    .bind(ev.operator_id.map(|o| o.to_string()))
    .bind(ev.kind.as_str())
    .bind(&ev.detail)
    .bind(ev.at.to_canonical())
    .bind(&ev.prev_hash)
    .bind(&ev.entry_hash)
    .execute(&mut *conn)
    .await?;
    tracing::debug!(
        seq = ev.seq,
        kind = ev.kind.as_str(),
        "evento de auditoria registrado"
    );
    Ok(ev)
}

fn seq_to_i64(seq: u64) -> Result<i64> {
    i64::try_from(seq).map_err(|_| MexError::InvalidInput("seq excede i64".into()).into())
}

fn audit_from_row(r: &SqliteRow) -> Result<AuditEvent> {
    let seq: i64 = r.try_get("seq")?;
    let case_id: Option<String> = r.try_get("case_id")?;
    let operator_id: Option<String> = r.try_get("operator_id")?;
    Ok(AuditEvent {
        seq: u64::try_from(seq)
            .map_err(|_| MexError::InvalidInput(format!("seq negativo: {seq}")))?,
        id: r.try_get::<String, _>("id")?.parse()?,
        case_id: case_id.map(|s| s.parse()).transpose()?,
        operator_id: operator_id.map(|s| s.parse()).transpose()?,
        kind: r.try_get::<String, _>("kind")?.parse()?,
        detail: r.try_get("detail")?,
        at: UtcTimestamp::parse_canonical(&r.try_get::<String, _>("at")?)?,
        prev_hash: r.try_get("prev_hash")?,
        entry_hash: r.try_get("entry_hash")?,
    })
}
