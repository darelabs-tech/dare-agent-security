//! No error message echoes input content (BLUEPRINT §4.1).
use dare_attack_path::{admit::admit_dir, AttackPathError};

#[test]
fn no_error_message_echoes_input() {
    let dir = tempfile::tempdir().unwrap();
    let canary = "sk-live-CANARY-VALUE-1234";
    std::fs::write(dir.path().join("broken.json"), format!("{{\"{canary}\": ")).unwrap();
    std::fs::write(
        dir.path().join("deep.json"),
        format!("{}\"{canary}\"{}", "[".repeat(80), "]".repeat(80)),
    )
    .unwrap();
    let admitted = admit_dir(0, dir.path()).unwrap();
    for file in ["broken.json", "deep.json", &format!("{canary}.json")] {
        let error: AttackPathError = admitted.read_json(file, "scenario").unwrap_err();
        assert!(error.is_refusal());
        let text = format!("{error} {error:?}");
        assert!(!text.contains("CANARY"), "{text}");
    }
}
