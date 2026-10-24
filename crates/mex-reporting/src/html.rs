//! Renderização HTML do relatório técnico.
//!
//! - Documento **autocontido**: sem scripts, fontes, imagens ou folhas de
//!   estilo externas (uso offline e arquivamento).
//! - **Todo** texto é escapado: caminhos e nomes vêm da origem e não são
//!   confiáveis (um nome de arquivo pode conter `<script>`).
//! - Função pura e determinística: o mesmo relatório produz os mesmos bytes.
//! - Layout claro, voltado a impressão.

use crate::model::{Coverage, TechnicalReport};
use mex_core::capability::ModificationRisk;
use mex_core::model::{AcquisitionOutcome, ArtifactStatus, AuthorizationKind, IntegrityStatus};
use mex_evidence::{FindingKind, Termination};
use std::collections::HashMap;
use std::fmt::Write;

/// Escapa texto para conteúdo e atributos HTML.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => {
                let _ = write!(o, "\\u{{{:04x}}}", c as u32);
            }
            c => o.push(c),
        }
    }
    o
}

fn bytes(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push('.');
        }
        out.push(ch);
    }
    format!("{out} B")
}

fn status_label(s: IntegrityStatus) -> (&'static str, &'static str) {
    match s {
        IntegrityStatus::Intact => ("ÍNTEGRO", "ok"),
        IntegrityStatus::Compromised => ("COMPROMETIDO — divergências detectadas", "bad"),
        IntegrityStatus::Incomplete => ("INCOMPLETO — pacote sem selo", "bad"),
    }
}

fn outcome_label(o: AcquisitionOutcome) -> &'static str {
    match o {
        AcquisitionOutcome::Complete => "Completa",
        AcquisitionOutcome::Partial => "Parcial",
        AcquisitionOutcome::Failed => "Falhou",
        AcquisitionOutcome::Cancelled => "Cancelada",
    }
}

fn termination_label(t: &Termination) -> String {
    match t {
        Termination::Normal => "Normal".into(),
        Termination::Cancelled => "Cancelada pelo operador".into(),
        Termination::Interrupted { reason } => format!("Interrompida: {reason}"),
    }
}

fn auth_kind_label(k: AuthorizationKind) -> &'static str {
    match k {
        AuthorizationKind::JudicialWarrant => "Decisão/mandado judicial",
        AuthorizationKind::OwnerConsent => "Consentimento do titular",
        AuthorizationKind::Other => "Outra base legal",
    }
}

fn risk_label(r: ModificationRisk) -> &'static str {
    match r {
        ModificationRisk::None => "Nenhum conhecido",
        ModificationRisk::Low => "Baixo",
        ModificationRisk::High => "Alto",
    }
}

fn coverage_label(c: Coverage) -> &'static str {
    match c {
        Coverage::Registered => "Registrado",
        Coverage::Partial => "Parcial",
        Coverage::NotRegistered => "Não registrado",
    }
}

fn finding_label(k: &FindingKind) -> String {
    match k {
        FindingKind::ManifestMissing => "Manifesto ausente".into(),
        FindingKind::SealMissing => "Selo do manifesto ausente".into(),
        FindingKind::SealMalformed => "Selo do manifesto em formato inválido".into(),
        FindingKind::SealMismatch { sealed, actual } => {
            format!("Manifesto não corresponde ao selo (selo {sealed}, calculado {actual})")
        }
        FindingKind::RegisteredHashMismatch { registered, actual } => format!(
            "Manifesto difere do registrado na aquisição (registrado {registered}, calculado {actual})"
        ),
        FindingKind::ManifestInvalid { detail } => format!("Manifesto inválido: {detail}"),
        FindingKind::ManifestInconsistent { detail } => format!("Manifesto incoerente: {detail}"),
        FindingKind::SumsMismatch => "SHA256SUMS ausente ou divergente do manifesto".into(),
        FindingKind::ArtifactMissing => "Artefato ausente".into(),
        FindingKind::NotRegularFile => "Não é arquivo regular (ex.: link simbólico)".into(),
        FindingKind::SizeMismatch { expected, actual } => {
            format!("Tamanho divergente (esperado {expected}, encontrado {actual})")
        }
        FindingKind::HashMismatch { expected, actual } => {
            format!("SHA-256 divergente (esperado {expected}, calculado {actual})")
        }
        FindingKind::FailedArtifactPresent => "Arquivo presente para artefato registrado como falho".into(),
        FindingKind::UnexpectedEntry => "Arquivo não consta do manifesto".into(),
        FindingKind::StagingLeftover => "Área temporária remanescente".into(),
        FindingKind::ReadError { detail } => format!("Erro de leitura: {detail}"),
    }
}

const CSS: &str = "\
body{font-family:'DejaVu Sans',Arial,sans-serif;font-size:10.5pt;color:#111;background:#fff;margin:24px;line-height:1.4}\
h1{font-size:16pt;margin:0 0 4px}h2{font-size:12.5pt;border-bottom:2px solid #222;padding-bottom:2px;margin-top:22px}\
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid #999;padding:3px 5px;vertical-align:top;text-align:left}\
th{background:#eee}table.kv th{width:28%}code,.mono{font-family:'DejaVu Sans Mono',monospace;font-size:9pt;word-break:break-all}\
.banner{padding:8px 12px;border:3px solid;font-weight:bold;font-size:12pt;margin:10px 0}\
.ok{border-color:#1b5e20;color:#1b5e20}.bad{border-color:#b71c1c;color:#b71c1c}\
.muted{color:#555}.sig{margin-top:48px}.sig div{display:inline-block;width:45%;border-top:1px solid #111;margin-right:4%;padding-top:4px}\
@media print{body{margin:12mm}h2{page-break-after:avoid}tr{page-break-inside:avoid}}";

struct H(String);

impl H {
    fn raw(&mut self, s: &str) {
        self.0.push_str(s);
    }
    fn h2(&mut self, n: u32, title: &str) {
        let _ = writeln!(self.0, "<h2>{n}. {}</h2>", esc(title));
    }
    fn kv_open(&mut self) {
        self.raw("<table class=\"kv\">\n");
    }
    fn kv(&mut self, k: &str, v: &str) {
        let _ = writeln!(self.0, "<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(v));
    }
    fn kv_mono(&mut self, k: &str, v: &str) {
        let _ = writeln!(
            self.0,
            "<tr><th>{}</th><td class=\"mono\">{}</td></tr>",
            esc(k),
            esc(v)
        );
    }
    fn close_table(&mut self) {
        self.raw("</table>\n");
    }
    fn p(&mut self, s: &str) {
        let _ = writeln!(self.0, "<p>{}</p>", esc(s));
    }
    fn list(&mut self, items: &[String], empty: &str) {
        if items.is_empty() {
            let _ = writeln!(self.0, "<p class=\"muted\">{}</p>", esc(empty));
        } else {
            self.raw("<ul>\n");
            for i in items {
                let _ = writeln!(self.0, "<li>{}</li>", esc(i));
            }
            self.raw("</ul>\n");
        }
    }
}

/// Renderiza o relatório em HTML.
pub fn render(r: &TechnicalReport) -> String {
    let mut h = H(String::with_capacity(64 * 1024));
    let title = format!("Relatório técnico de aquisição — caso {}", r.case.number);
    let _ = write!(
        h.0,
        "<!DOCTYPE html>\n<html lang=\"pt-BR\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n\
         <title>{}</title>\n<style>{CSS}</style>\n</head>\n<body>\n",
        esc(&title)
    );
    let _ = writeln!(h.0, "<h1>{}</h1>", esc(&title));
    let _ = writeln!(
        h.0,
        "<p class=\"muted\">BlackBit MEX · relatório <span class=\"mono\">{}</span> · emitido em {} (UTC) · formato {}</p>",
        esc(&r.report_id.to_string()),
        esc(&r.generated_at.to_canonical()),
        esc(r.format)
    );
    let (label, class) = status_label(r.integrity.status);
    let outcome = r
        .manifest
        .as_ref()
        .map(|m| outcome_label(m.outcome))
        .unwrap_or("desconhecido (manifesto indisponível)");
    let _ = writeln!(
        h.0,
        "<div class=\"banner {class}\">Integridade do pacote na emissão: {} · Resultado da aquisição: {}</div>",
        esc(label),
        esc(outcome)
    );

    // 1. Identificação
    h.h2(1, "Identificação");
    h.kv_open();
    h.kv("Caso", &format!("{} — {}", r.case.number, r.case.title));
    h.kv_mono("ID do caso", &r.case.id.to_string());
    h.kv_mono("ID da aquisição", &r.acquisition_id.to_string());
    h.kv(
        "Emitido por",
        &format!(
            "{} (matrícula {}, {})",
            r.generated_by.full_name, r.generated_by.badge, r.generated_by.organization
        ),
    );
    h.kv_mono("Pacote de evidências", &r.package_path);
    h.close_table();

    let mut names: HashMap<String, String> = HashMap::new();
    names.insert(
        r.generated_by.id.to_string(),
        r.generated_by.full_name.clone(),
    );

    match &r.manifest {
        None => {
            h.h2(2, "Manifesto");
            let _ = writeln!(
                h.0,
                "<p class=\"bad\"><strong>Manifesto indisponível:</strong> {}. As seções de proveniência e inventário não podem ser apresentadas.</p>",
                esc(r.manifest_problem.as_deref().unwrap_or("motivo desconhecido"))
            );
        }
        Some(m) => {
            names.insert(m.operator.id.to_string(), m.operator.full_name.clone());
            if r.integrity.status != IntegrityStatus::Intact {
                h.raw("<p class=\"bad\"><strong>Atenção:</strong> o pacote não está íntegro. Os dados abaixo foram lidos do manifesto presente no pacote e podem ter sido alterados; ver seção 5.</p>\n");
            }
            // 2. Autorização
            h.h2(2, "Autorização");
            h.kv_open();
            let a = &m.authorization;
            let mut kind = auth_kind_label(a.kind).to_string();
            if let Some(d) = &a.kind_detail {
                kind.push_str(&format!(" — {d}"));
            }
            h.kv("Natureza", &kind);
            h.kv("Referência", &a.reference);
            h.kv("Autoridade emissora", &a.issuer);
            h.kv(
                "Escopo/observações",
                a.scope_notes.as_deref().unwrap_or("—"),
            );
            h.kv_mono(
                "SHA-256 do documento",
                &a.document_sha256
                    .as_ref()
                    .map(|d| d.hex.clone())
                    .unwrap_or_else(|| "não anexado".into()),
            );
            h.kv("Registrada em (UTC)", &a.recorded_at.to_canonical());
            h.close_table();
            h.p("O MEX registra a autorização informada pelo operador; não avalia sua validade jurídica.");

            // 3. Dispositivo e aquisição
            h.h2(3, "Dispositivo e aquisição");
            h.kv_open();
            let d = &m.device;
            h.kv("Plataforma", d.platform.as_str());
            h.kv_mono("Serial (auto-declarado)", &d.serial);
            h.kv("Fabricante", d.manufacturer.as_deref().unwrap_or("—"));
            h.kv("Modelo", d.model.as_deref().unwrap_or("—"));
            h.kv("Versão do sistema", d.os_version.as_deref().unwrap_or("—"));
            h.kv(
                "Patch de segurança",
                d.security_patch.as_deref().unwrap_or("—"),
            );
            h.kv_mono("ID no inventário", &m.device_id.to_string());
            h.kv(
                "Executada por",
                &format!(
                    "{} (matrícula {}, {})",
                    m.operator.full_name, m.operator.badge, m.operator.organization
                ),
            );
            h.kv(
                "Método (adaptador)",
                &format!("{} {}", m.adapter.id, m.adapter.version),
            );
            h.kv("Capacidade", m.adapter.capability.as_str());
            h.kv(
                "Risco de modificação declarado",
                risk_label(m.adapter.modification_risk),
            );
            h.kv("Pré-requisitos", &m.adapter.prerequisites.join("; "));
            h.kv("Restrições", &m.adapter.restrictions.join("; "));
            h.kv("Início (UTC)", &m.started_at.to_canonical());
            h.kv("Fim (UTC)", &m.finished_at.to_canonical());
            h.kv("Término", &termination_label(&m.termination));
            h.kv("Resultado", outcome_label(m.outcome));
            h.kv(
                "Totais",
                &format!(
                    "{} completos, {} falhos, {} não adquiridos, {} em artefatos completos",
                    m.totals.artifacts_complete,
                    m.totals.artifacts_failed,
                    m.totals.not_acquired,
                    bytes(m.totals.bytes_complete)
                ),
            );
            h.close_table();
        }
    }

    // 4. Software
    h.h2(4, "Versões de software");
    h.raw("<table>\n<tr><th>Módulo</th><th>Versão</th></tr>\n");
    for mv in &r.software {
        let _ = writeln!(
            h.0,
            "<tr><td>{}</td><td>{}</td></tr>",
            esc(&mv.name),
            esc(&mv.version)
        );
    }
    if let Some(m) = &r.manifest {
        let _ = write!(
            h.0,
            "<tr><td>{} (na aquisição)</td><td>{}</td></tr>\n<tr><td>adaptador {} (na aquisição)</td><td>{}</td></tr>\n",
            esc(&m.software.name),
            esc(&m.software.version),
            esc(&m.adapter.id),
            esc(&m.adapter.version)
        );
    }
    h.close_table();

    // 5. Integridade
    h.h2(5, "Verificação de integridade (executada na emissão)");
    h.kv_open();
    h.kv("Resultado", label);
    h.kv(
        "Verificado em (UTC)",
        &r.integrity.verified_at.to_canonical(),
    );
    h.kv_mono(
        "SHA-256 do manifesto registrado na aquisição",
        &r.integrity.registered_manifest_sha256.hex,
    );
    h.kv_mono(
        "SHA-256 do manifesto presente no pacote",
        &r.integrity
            .computed_manifest_sha256
            .as_ref()
            .map(|d| d.hex.clone())
            .unwrap_or_else(|| "indisponível".into()),
    );
    h.kv(
        "Artefatos conferidos",
        &r.integrity.artifacts_checked.to_string(),
    );
    h.kv("Bytes relidos", &bytes(r.integrity.bytes_verified));
    h.close_table();
    if r.integrity.findings.is_empty() {
        h.p("Nenhuma divergência encontrada.");
    } else {
        h.raw("<table>\n<tr><th>Objeto</th><th>Divergência</th></tr>\n");
        for f in &r.integrity.findings {
            let _ = writeln!(
                h.0,
                "<tr><td class=\"mono\">{}</td><td>{}</td></tr>",
                esc(&f.subject),
                esc(&finding_label(&f.kind))
            );
        }
        h.close_table();
    }

    if let Some(m) = &r.manifest {
        // 6. Inventário
        h.h2(6, "Inventário de artefatos");
        h.raw("<table>\n<tr><th>#</th><th>Caminho no pacote</th><th>Caminho na origem</th><th>Tamanho</th><th>Modificado na origem (UTC)</th><th>SHA-256</th><th>Estado</th></tr>\n");
        for (i, a) in m.artifacts.iter().enumerate() {
            let state = match &a.status {
                ArtifactStatus::Complete { .. } => "Completo".to_string(),
                ArtifactStatus::Failed { reason } => format!("Falhou: {reason}"),
                ArtifactStatus::Pending => "Pendente".to_string(),
            };
            let _ = writeln!(
                h.0,
                "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
                i + 1,
                esc(a.stored_path.as_str()),
                esc(a.source_path.as_deref().unwrap_or("—")),
                esc(&bytes(a.size_bytes)),
                esc(&a.source_modified.map(|t| t.to_canonical()).unwrap_or_else(|| "—".into())),
                esc(&a.digest().map(|d| d.hex.clone()).unwrap_or_else(|| "—".into())),
                esc(&state)
            );
        }
        if m.artifacts.is_empty() {
            h.raw("<tr><td colspan=\"7\" class=\"muted\">Nenhum artefato.</td></tr>\n");
        }
        h.close_table();

        // 7. Limitações e falhas
        h.h2(
            7,
            "Limitações, falhas e operações potencialmente modificadoras",
        );
        h.raw("<h3>Itens não adquiridos</h3>\n");
        let not: Vec<String> = m
            .not_acquired
            .iter()
            .map(|f| format!("{} — {}", f.source_path.as_deref().unwrap_or("?"), f.reason))
            .collect();
        h.list(&not, "Nenhum item relatado como não adquirido.");
        h.raw("<h3>Limitações</h3>\n");
        h.list(&m.limitations, "Nenhuma limitação registrada.");
        h.raw("<h3>Operações potencialmente modificadoras do dispositivo</h3>\n");
        h.list(
            &m.modifying_operations,
            "Nenhuma operação modificadora foi registrada pelo adaptador.",
        );
    }

    // 8. Cadeia de custódia
    h.h2(8, "Cadeia de custódia (eventos do caso)");
    h.kv_open();
    h.kv(
        "Verificação da cadeia completa",
        &if r.custody.chain_intact {
            "Íntegra".to_string()
        } else {
            format!(
                "VIOLADA: {}",
                r.custody.chain_problem.as_deref().unwrap_or("?")
            )
        },
    );
    h.kv(
        "Eventos na cadeia completa",
        &r.custody.chain_length.to_string(),
    );
    h.kv_mono(
        "Hash do último evento (âncora)",
        r.custody.chain_head_hash.as_deref().unwrap_or("—"),
    );
    h.close_table();
    h.p("Registre o hash do último evento fora do sistema (por exemplo, neste relatório impresso e assinado): ele permite detectar a remoção posterior de eventos da cadeia.");
    h.raw("<table>\n<tr><th>Seq.</th><th>Quando (UTC)</th><th>Tipo</th><th>Operador</th><th>Detalhe</th><th>Hash do evento</th></tr>\n");
    for e in &r.custody.events {
        let op = e
            .operator_id
            .map(|id| {
                names
                    .get(&id.to_string())
                    .cloned()
                    .unwrap_or_else(|| id.to_string())
            })
            .unwrap_or_else(|| "—".into());
        let _ = writeln!(
            h.0,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td></tr>",
            e.seq,
            esc(&e.at.to_canonical()),
            esc(e.kind.as_str()),
            esc(&op),
            esc(&e.detail),
            esc(&e.entry_hash)
        );
    }
    h.close_table();

    // 9. Considerações legais
    h.h2(
        9,
        "Considerações sobre a cadeia de custódia (CPP, arts. 158-A a 158-F)",
    );
    h.p(r.legal.notice);
    h.raw("<table>\n<tr><th>Etapa (art. 158-B)</th><th>Situação no MEX</th><th>Observação</th></tr>\n");
    for s in &r.legal.stages {
        let _ = writeln!(
            h.0,
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(s.stage),
            esc(coverage_label(s.coverage)),
            esc(s.note)
        );
    }
    h.close_table();

    h.raw("<div class=\"sig\"><div>Perito(a) responsável — nome, matrícula e assinatura</div><div>Data</div></div>\n");
    h.raw("<p class=\"muted\">O SHA-256 deste arquivo é registrado no banco do MEX e na cadeia de custódia (evento <code>exported</code>) no momento da emissão.</p>\n");
    h.raw("</body>\n</html>\n");
    h.0
}
