//! Testes de integração do núcleo (Milestone 1).
//!
//! Exercitam os contratos públicos (traits, job, sink, outcome) usando
//! exclusivamente o mock. Nenhum dispositivo real é acessado.

use mex_core::cancel::CancellationToken;
use mex_core::capability::CapabilityKind;
use mex_core::ids::AcquisitionId;
use mex_core::integrity::{hash_reader, sha256_hex, Digest256};
use mex_core::job::AcquisitionJob;
use mex_core::mock::{
    mock_content, simulated_device, InMemorySink, MockAdapter, MockArtifact, MockProvider,
    MockScenario,
};
use mex_core::model::{AcquisitionOutcome, AdbState, ArtifactFailure, ArtifactStatus, Platform};
use mex_core::path::EvidencePath;
use mex_core::state::JobState;
use mex_core::timestamp::UtcTimestamp;
use mex_core::traits::{
    AcquisitionAdapter, AcquisitionRequest, ArtifactSpec, CapabilityResolver, DeviceProvider,
    EvidenceSink,
};
use mex_core::MexError;
use std::io::Read;

// ---------------------------------------------------------------- hashing

/// Vetor conhecido (FIPS 180-2): SHA-256 de "abc".
#[test]
fn sha256_known_vector() {
    assert_eq!(
        sha256_hex(b"abc").hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// SHA-256 do buffer vazio.
#[test]
fn sha256_empty_vector() {
    assert_eq!(
        sha256_hex(b"").hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

/// Vetor longo (FIPS 180-2): um milhão de 'a', lido em streaming.
#[test]
fn sha256_million_a_streaming() {
    let reader = std::io::repeat(b'a').take(1_000_000);
    let (d, n) = hash_reader(reader).unwrap();
    assert_eq!(n, 1_000_000);
    assert_eq!(
        d.hex,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

/// Streaming de um fluxo grande (256 MiB) com memória constante: o
/// resultado coincide com o hash incremental em blocos de tamanho diferente.
#[test]
fn large_stream_hash_is_consistent() {
    const SIZE: u64 = 256 * 1024 * 1024;
    let (a, n) = hash_reader(std::io::repeat(0xAB).take(SIZE)).unwrap();
    assert_eq!(n, SIZE);

    let mut h = mex_core::integrity::StreamHasher::new();
    let block = vec![0xABu8; 4096 + 3];
    let mut left = SIZE;
    while left > 0 {
        let n = left.min(block.len() as u64) as usize;
        h.update(&block[..n]);
        left -= n as u64;
    }
    assert_eq!(h.finalize(), a);
}

// ------------------------------------------------- descoberta/capacidades

#[tokio::test]
async fn mock_provider_lists_only_simulated_devices() {
    let p = MockProvider::new(vec![simulated_device("SIM123", AdbState::Device)]).unwrap();
    let devices = p.list_devices().await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].serial, "SIM123");
    assert_eq!(devices[0].platform, Platform::Simulated);

    let mut real = simulated_device("REAL", AdbState::Device);
    real.platform = Platform::Android;
    assert!(MockProvider::new(vec![real]).is_err());
}

#[test]
fn presence_does_not_imply_capability() {
    let adapter = MockAdapter::new(scenario(vec![]));
    for state in [
        AdbState::Unauthorized,
        AdbState::Offline,
        AdbState::Other("recovery".into()),
    ] {
        let caps = adapter.resolve(&simulated_device("X", state.clone()));
        assert!(!caps.is_empty());
        assert!(caps.iter().all(|c| !c.is_available()), "{state:?}");
    }
}

#[test]
fn mock_refuses_real_devices() {
    let adapter = MockAdapter::new(scenario(vec![]));
    let mut real = simulated_device("REAL", AdbState::Device);
    real.platform = Platform::Android;
    assert!(adapter.resolve(&real).iter().all(|c| !c.is_available()));
}

// --------------------------------------------------- aquisição em streaming

fn scenario(artifacts: Vec<MockArtifact>) -> MockScenario {
    MockScenario {
        artifacts,
        chunk_size: 64 * 1024,
        disconnect_after_bytes: None,
        not_acquired: Vec::new(),
    }
}

fn three_artifacts() -> Vec<MockArtifact> {
    vec![
        MockArtifact {
            path: "device/info.json".into(),
            size: 1_000,
            seed: 1,
        },
        MockArtifact {
            path: "files/a.bin".into(),
            size: 3 * 1024 * 1024 + 5,
            seed: 2,
        },
        MockArtifact {
            path: "files/b.bin".into(),
            size: 200_000,
            seed: 3,
        },
    ]
}

fn request(acq: AcquisitionId) -> AcquisitionRequest {
    AcquisitionRequest {
        acquisition_id: acq,
        capability: CapabilityKind::LocalImport,
        device: simulated_device("SIM123", AdbState::Device),
    }
}

/// Simula o que o motor fará: conduz o job e deriva o resultado do sink.
fn finish_job(
    job: &mut AcquisitionJob,
    sink: &InMemorySink,
    result: &Result<mex_core::traits::AdapterReport, MexError>,
) -> AcquisitionOutcome {
    let t = UtcTimestamp::now();
    let completed = sink.artifacts().iter().filter(|a| a.is_complete()).count();
    let failed_in_sink = sink.artifacts().len() - completed;
    let not_acquired = result.as_ref().map(|r| r.not_acquired.len()).unwrap_or(0);
    let cancelled = matches!(result, Err(MexError::Cancelled));
    let interrupted = result.is_err() && !cancelled;
    let outcome = AcquisitionOutcome::derive(
        cancelled,
        completed,
        failed_in_sink + not_acquired,
        interrupted,
    );
    if outcome == AcquisitionOutcome::Cancelled {
        job.transition(JobState::Cancelled, Some("cancelado pelo operador"), t)
            .unwrap();
    } else {
        job.transition(JobState::Finalizing, None, t).unwrap();
        let reason = (outcome == AcquisitionOutcome::Failed).then_some("nenhum artefato adquirido");
        job.transition(JobState::terminal_for(outcome), reason, t)
            .unwrap();
    }
    outcome
}

fn running_job(acq: AcquisitionId) -> AcquisitionJob {
    let t = UtcTimestamp::now();
    let mut job = AcquisitionJob::new(acq, CapabilityKind::LocalImport, t);
    for s in [JobState::Validating, JobState::Ready, JobState::Running] {
        job.transition(s, None, t).unwrap();
    }
    job
}

#[tokio::test]
async fn mock_streaming_acquisition_completes_with_correct_hashes() {
    let acq = AcquisitionId::new();
    let arts = three_artifacts();
    let adapter = MockAdapter::new(scenario(arts.clone()));
    let mut sink = InMemorySink::new(acq);
    let mut job = running_job(acq);

    let result = adapter
        .acquire(&request(acq), &mut sink, &CancellationToken::new())
        .await;
    assert!(result.is_ok());

    let records = sink.artifacts();
    assert_eq!(records.len(), 3);
    for (rec, art) in records.iter().zip(&arts) {
        let expected = mock_content(art.seed, art.size);
        assert_eq!(rec.size_bytes, art.size);
        assert_eq!(rec.digest().unwrap(), &sha256_hex(&expected));
        assert_eq!(sink.content(rec.id).unwrap(), expected.as_slice());
    }
    assert_eq!(
        finish_job(&mut job, &sink, &result),
        AcquisitionOutcome::Complete
    );
    assert_eq!(job.state(), JobState::Completed);
}

#[tokio::test]
async fn cancellation_mid_artifact_never_marks_it_complete() {
    let acq = AcquisitionId::new();
    let adapter = MockAdapter::new(scenario(three_artifacts()));
    let cancel = CancellationToken::new();
    // Cancela no meio do segundo artefato (após ~1 MiB dele).
    let mut sink =
        InMemorySink::new(acq).cancel_when_bytes_reach(1_000 + 1024 * 1024, cancel.clone());
    let mut job = running_job(acq);

    let result = adapter.acquire(&request(acq), &mut sink, &cancel).await;
    assert!(matches!(result, Err(MexError::Cancelled)));

    let recs = sink.artifacts();
    assert_eq!(
        recs.len(),
        2,
        "terceiro artefato não deve ter sido iniciado"
    );
    assert!(recs[0].is_complete());
    assert!(
        matches!(&recs[1].status, ArtifactStatus::Failed { reason } if reason.contains("abortado"))
    );
    assert!(recs[1].digest().is_none());
    assert!(sink.content(recs[1].id).is_none());

    assert_eq!(
        finish_job(&mut job, &sink, &result),
        AcquisitionOutcome::Cancelled
    );
    assert_eq!(job.state(), JobState::Cancelled);
}

#[tokio::test]
async fn disconnection_yields_partial_with_failed_artifact() {
    let acq = AcquisitionId::new();
    let mut sc = scenario(three_artifacts());
    sc.disconnect_after_bytes = Some(1_000 + 512 * 1024);
    let adapter = MockAdapter::new(sc);
    let mut sink = InMemorySink::new(acq);
    let mut job = running_job(acq);

    let result = adapter
        .acquire(&request(acq), &mut sink, &CancellationToken::new())
        .await;
    assert!(matches!(result, Err(MexError::DeviceDisconnected(_))));

    let recs = sink.artifacts();
    assert_eq!(recs.len(), 2);
    assert!(recs[0].is_complete());
    // O writer foi descartado sem commit: registrado como falho pelo Drop.
    assert!(
        matches!(&recs[1].status, ArtifactStatus::Failed { reason } if reason.contains("sem commit"))
    );

    assert_eq!(
        finish_job(&mut job, &sink, &result),
        AcquisitionOutcome::Partial
    );
    assert_eq!(job.state(), JobState::Partial);
}

#[tokio::test]
async fn disconnection_before_any_artifact_is_failed() {
    let acq = AcquisitionId::new();
    let mut sc = scenario(three_artifacts());
    sc.disconnect_after_bytes = Some(0);
    let adapter = MockAdapter::new(sc);
    let mut sink = InMemorySink::new(acq);
    let mut job = running_job(acq);

    let result = adapter
        .acquire(&request(acq), &mut sink, &CancellationToken::new())
        .await;
    assert!(result.is_err());
    assert_eq!(
        finish_job(&mut job, &sink, &result),
        AcquisitionOutcome::Failed
    );
    assert_eq!(job.state(), JobState::Failed);
}

#[tokio::test]
async fn not_acquired_items_make_outcome_partial() {
    let acq = AcquisitionId::new();
    let mut sc = scenario(three_artifacts());
    sc.not_acquired = vec![ArtifactFailure {
        source_path: Some("/simulated/protegido".into()),
        reason: "permissão negada".into(),
    }];
    let adapter = MockAdapter::new(sc);
    let mut sink = InMemorySink::new(acq);
    let mut job = running_job(acq);
    let result = adapter
        .acquire(&request(acq), &mut sink, &CancellationToken::new())
        .await;
    assert!(result.is_ok());
    assert_eq!(
        finish_job(&mut job, &sink, &result),
        AcquisitionOutcome::Partial
    );
}

#[tokio::test]
async fn unavailable_capability_is_refused() {
    let acq = AcquisitionId::new();
    let adapter = MockAdapter::new(scenario(three_artifacts()));
    let mut sink = InMemorySink::new(acq);
    let mut req = request(acq);
    req.device.adb_state = Some(AdbState::Unauthorized);
    let r = adapter
        .acquire(&req, &mut sink, &CancellationToken::new())
        .await;
    assert!(matches!(r, Err(MexError::UnsupportedCapability(_))));
    assert!(sink.artifacts().is_empty());
}

// ------------------------------------------------- contrato do sink

#[tokio::test]
async fn size_mismatch_fails_commit() {
    let mut sink = InMemorySink::new(AcquisitionId::new());
    let mut w = sink
        .begin_artifact(ArtifactSpec {
            stored_path: EvidencePath::new("x.bin").unwrap(),
            source_path: None,
            source_modified: None,
            expected_size: Some(10),
        })
        .await
        .unwrap();
    w.write(b"12345").await.unwrap();
    assert!(w.commit().await.is_err());
    assert_eq!(sink.artifacts().len(), 1);
    assert!(!sink.artifacts()[0].is_complete());
}

#[tokio::test]
async fn completed_artifact_cannot_be_overwritten() {
    let mut sink = InMemorySink::new(AcquisitionId::new());
    let spec = ArtifactSpec {
        stored_path: EvidencePath::new("x.bin").unwrap(),
        source_path: None,
        source_modified: None,
        expected_size: None,
    };
    let mut w = sink.begin_artifact(spec.clone()).await.unwrap();
    w.write(b"original").await.unwrap();
    w.commit().await.unwrap();
    assert!(sink.begin_artifact(spec).await.is_err());
}

/// Corrupção posterior de um artefato é detectada pela re-verificação.
#[tokio::test]
async fn artifact_corruption_is_detected_on_reverification() {
    let acq = AcquisitionId::new();
    let adapter = MockAdapter::new(scenario(three_artifacts()));
    let mut sink = InMemorySink::new(acq);
    adapter
        .acquire(&request(acq), &mut sink, &CancellationToken::new())
        .await
        .unwrap();

    let rec = &sink.artifacts()[1];
    let mut copy = sink.content(rec.id).unwrap().to_vec();
    assert!(sha256_hex(&copy).verify_eq(rec.digest().unwrap()).is_ok());
    copy[123_456] ^= 0x01; // um único bit
    let recomputed: Digest256 = sha256_hex(&copy);
    assert!(matches!(
        recomputed.verify_eq(rec.digest().unwrap()),
        Err(MexError::IntegrityMismatch { .. })
    ));
}
