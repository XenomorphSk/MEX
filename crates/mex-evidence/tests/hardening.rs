//! Hardening do Evidence Engine (Milestone 7): operações ancoradas em
//! descritores, sem sobrescrita e com permissões mínimas.
//!
//! As garantias vêm da semântica das chamadas de sistema (`openat` com
//! `O_NOFOLLOW` a partir de descritores mantidos abertos e
//! `renameat2(RENAME_NOREPLACE)`); os testes abaixo as exercitam, inclusive
//! sob uma corrida real com outra thread alterando o pacote.

#![cfg(target_os = "linux")]

use mex_core::ids::AcquisitionId;
use mex_core::path::EvidencePath;
use mex_core::traits::{ArtifactSpec, EvidenceSink};
use mex_evidence::{DiskEvidenceSink, SinkOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn spec(path: &str) -> ArtifactSpec {
    ArtifactSpec {
        stored_path: EvidencePath::new(path).unwrap(),
        source_path: None,
        source_modified: None,
        expected_size: None,
    }
}

async fn put(sink: &mut DiskEvidenceSink, path: &str, data: &[u8]) -> mex_core::Result<()> {
    let mut w = sink.begin_artifact(spec(path)).await?;
    w.write(data).await?;
    w.commit().await.map(|_| ())
}

fn count_files(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|rd| rd.count()).unwrap_or(0)
}

/// Trocar `artifacts/` por um link para fora depois da criação não desvia a
/// gravação: o descritor continua no diretório original.
#[tokio::test]
async fn swapping_artifacts_dir_for_symlink_does_not_redirect() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut sink =
        DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), SinkOptions::default())
            .await
            .unwrap();
    let pkg = sink.package_dir().to_path_buf();
    std::fs::rename(pkg.join("artifacts"), pkg.join("artifacts_movido")).unwrap();
    std::os::unix::fs::symlink(outside.path(), pkg.join("artifacts")).unwrap();

    put(&mut sink, "x.bin", b"evidencia").await.unwrap();

    assert_eq!(
        count_files(outside.path()),
        0,
        "nada pode ser gravado fora do pacote"
    );
    assert_eq!(
        std::fs::read(pkg.join("artifacts_movido/x.bin")).unwrap(),
        b"evidencia"
    );
}

/// Corrida real: outra thread alterna `artifacts/files` entre diretório real
/// e link para fora enquanto o sink publica artefatos sob `files/`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn racing_symlink_swaps_never_write_outside() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut sink =
        DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), SinkOptions::default())
            .await
            .unwrap();
    let artifacts = sink.package_dir().join("artifacts");
    put(&mut sink, "files/semente.bin", b"0").await.unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let attacker = {
        let (stop, artifacts, target) = (
            Arc::clone(&stop),
            artifacts.clone(),
            outside.path().to_path_buf(),
        );
        std::thread::spawn(move || {
            let (real, held) = (artifacts.join("files"), artifacts.join("files_real"));
            let mut swaps = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if std::fs::rename(&real, &held).is_ok() {
                    let _ = std::os::unix::fs::symlink(&target, &real);
                    std::thread::yield_now();
                    let _ = std::fs::remove_file(&real);
                    let _ = std::fs::rename(&held, &real);
                    swaps += 1;
                }
            }
            swaps
        })
    };

    let (mut ok, mut refused) = (0, 0);
    for i in 0..300 {
        match put(&mut sink, &format!("files/a{i:03}.bin"), b"dado").await {
            Ok(()) => ok += 1,
            Err(_) => refused += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = attacker.join().unwrap();

    assert_eq!(
        count_files(outside.path()),
        0,
        "gravação desviada para fora do pacote"
    );
    assert_eq!(ok + refused, 300);
    assert!(
        swaps > 0,
        "a thread atacante precisa ter alternado o diretório"
    );
    // Todo artefato aceito está dentro do pacote (no diretório real).
    let mut inside = 0;
    for d in ["files", "files_real"] {
        inside += std::fs::read_dir(artifacts.join(d))
            .map(|rd| {
                rd.filter(|e| e.as_ref().unwrap().file_type().unwrap().is_file())
                    .count()
            })
            .unwrap_or(0);
    }
    assert_eq!(
        inside,
        ok + 1,
        "artefatos aceitos = arquivos no pacote (+ semente)"
    );
    eprintln!("corrida: {swaps} trocas, {ok} aceitos, {refused} recusados, 0 fora do pacote");
}

/// Um arquivo plantado no destino nunca é sobrescrito.
#[tokio::test]
async fn existing_destination_is_never_overwritten() {
    let tmp = tempfile::tempdir().unwrap();
    let mut sink =
        DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), SinkOptions::default())
            .await
            .unwrap();
    let planted = sink.package_dir().join("artifacts/x.bin");
    std::fs::write(&planted, b"plantado").unwrap();
    let e = put(&mut sink, "x.bin", b"evidencia").await.unwrap_err();
    assert!(e.to_string().contains("não será sobrescrito"), "{e}");
    assert_eq!(std::fs::read(&planted).unwrap(), b"plantado");
    assert!(!sink.artifacts()[0].is_complete());
    assert_eq!(
        count_files(&sink.package_dir().join(".staging")),
        0,
        "temporário removido"
    );
}

/// Permissões mínimas: diretórios 0700, arquivos 0600 (nada para grupo/outros).
#[tokio::test]
async fn package_permissions_are_minimal() {
    let tmp = tempfile::tempdir().unwrap();
    let mut sink =
        DiskEvidenceSink::create(tmp.path(), AcquisitionId::new(), SinkOptions::default())
            .await
            .unwrap();
    put(&mut sink, "a/b/c.bin", b"x").await.unwrap();
    let pkg = sink.package_dir().to_path_buf();
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
    for d in ["", "artifacts", "artifacts/a", "artifacts/a/b"] {
        assert_eq!(
            mode(&pkg.join(d)) & 0o077,
            0,
            "diretório {d:?}: {:o}",
            mode(&pkg.join(d))
        );
    }
    assert_eq!(mode(&pkg.join("artifacts/a/b/c.bin")) & 0o077, 0);
}

/// Fluxo completo numa raiz arbitrária (ex.: mídia FAT/exFAT), indicada por
/// `MEX_TEST_EVIDENCE_ROOT`. Ignorado quando a variável não está definida.
#[tokio::test]
async fn works_on_configured_evidence_root() {
    let Some(root) = std::env::var_os("MEX_TEST_EVIDENCE_ROOT") else {
        eprintln!("MEX_TEST_EVIDENCE_ROOT não definido; teste ignorado");
        return;
    };
    let dir = tempfile::tempdir_in(root).unwrap();
    let mut sink =
        DiskEvidenceSink::create(dir.path(), AcquisitionId::new(), SinkOptions::default())
            .await
            .unwrap();
    put(&mut sink, "files/a.bin", b"conteudo").await.unwrap();
    assert!(put(&mut sink, "files/a.bin", b"de novo").await.is_err());
    let planted = sink.package_dir().join("artifacts/files/b.bin");
    std::fs::write(&planted, b"plantado").unwrap();
    assert!(put(&mut sink, "files/b.bin", b"x").await.is_err());
    assert_eq!(std::fs::read(&planted).unwrap(), b"plantado");
    let pkg = sink.package_dir().to_path_buf();
    assert_eq!(
        std::fs::read(pkg.join("artifacts/files/a.bin")).unwrap(),
        b"conteudo"
    );
}
