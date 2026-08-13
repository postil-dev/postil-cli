use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const CONTRACT_MANIFEST: &str = "bench/review-contract-sources.json";
const REQUIRED_PATHS: &[&str] = &["Cargo.lock", "Cargo.toml", "build.rs"];

fn main() {
    let repository_root = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .expect("Cargo must set CARGO_MANIFEST_DIR for build scripts"),
    );
    let manifest_path = repository_root.join(CONTRACT_MANIFEST);
    let declared: Vec<String> = serde_json::from_str(
        &fs::read_to_string(&manifest_path).expect("review contract manifest must be readable"),
    )
    .expect("review contract manifest must be a JSON string array");

    let mut expected = REQUIRED_PATHS
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    collect_rust_sources(
        &repository_root,
        &repository_root.join("src"),
        &mut expected,
    );
    expected.sort_unstable();

    assert_eq!(
        declared, expected,
        "review contract manifest must exactly cover required manifests and every src/**/*.rs file"
    );

    for path in &expected {
        assert!(
            is_safe_relative_path(path),
            "invalid review contract path {path:?}"
        );
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed={CONTRACT_MANIFEST}");

    let generated = render_contract_sources(&expected);
    let output_path = PathBuf::from(env::var("OUT_DIR").expect("Cargo must set OUT_DIR"))
        .join("review_contract_sources.rs");
    fs::write(output_path, generated).expect("generated review contract sources must be writable");
}

fn collect_rust_sources(repository_root: &Path, directory: &Path, paths: &mut Vec<String>) {
    let mut entries = fs::read_dir(directory)
        .expect("source directory must be readable")
        .collect::<Result<Vec<_>, _>>()
        .expect("source directory entries must be readable");
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(repository_root, &path, paths);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(repository_root)
                .expect("source path must be inside the repository root")
                .to_str()
                .expect("review contract paths must be UTF-8")
                .replace('\\', "/");
            paths.push(relative);
        }
    }
}

fn is_safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
}

fn render_contract_sources(paths: &[String]) -> String {
    let mut output =
        String::from("#[cfg(test)]\npub(crate) const REVIEW_CONTRACT_PATHS: &[&str] = &[\n");
    for path in paths {
        output.push_str(&format!("    {path:?},\n"));
    }
    output.push_str("];\n\npub(crate) const REVIEW_CONTRACT_SOURCES: &[(&str, &str)] = &[\n");
    for path in paths {
        output.push_str(&format!(
            "    ({path:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{path}\"))),\n"
        ));
    }
    output.push_str("];\n");
    output
}
