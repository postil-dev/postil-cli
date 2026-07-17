#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn system_command(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set"))
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("{name} is available for the installer test"))
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

struct InstallerFixture {
    _root: tempfile::TempDir,
    tools: PathBuf,
    artifacts: PathBuf,
    bin: PathBuf,
}

impl InstallerFixture {
    fn new(with_cosign: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let tools = root.path().join("tools");
        let artifacts = root.path().join("artifacts");
        let payload = root.path().join("payload");
        let bin = root.path().join("bin");
        for directory in [&tools, &artifacts, &payload, &bin] {
            fs::create_dir(directory).unwrap();
        }

        for command in [
            "awk",
            "chmod",
            "cp",
            "grep",
            "gzip",
            "head",
            "ldd",
            "ls",
            "mkdir",
            "mktemp",
            "mv",
            "rm",
            "sha256sum",
            "tar",
            "uname",
        ] {
            symlink(system_command(command), tools.join(command)).unwrap();
        }

        write_executable(
            &payload.join("postil"),
            "#!/bin/sh\necho 'postil test-version'\n",
        );
        let archive = artifacts.join("postil-x86_64-unknown-linux-gnu.tar.gz");
        let status = Command::new(system_command("tar"))
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&payload)
            .arg("postil")
            .status()
            .unwrap();
        assert!(status.success());
        let digest = Sha256::digest(fs::read(&archive).unwrap());
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        fs::write(
            artifacts.join("postil-x86_64-unknown-linux-gnu.tar.gz.sha256"),
            format!("{digest}  postil-x86_64-unknown-linux-gnu.tar.gz\n"),
        )
        .unwrap();

        write_executable(
            &tools.join("curl"),
            "#!/bin/sh\ncase \"$2\" in\n  *.tar.gz.sha256) cp \"$POSTIL_TEST_ARTIFACTS/postil-x86_64-unknown-linux-gnu.tar.gz.sha256\" \"$4\" ;;\n  *.tar.gz.sig|*.tar.gz.pem) : > \"$4\" ;;\n  *.tar.gz) cp \"$POSTIL_TEST_ARTIFACTS/postil-x86_64-unknown-linux-gnu.tar.gz\" \"$4\" ;;\n  *) exit 1 ;;\nesac\n",
        );
        if with_cosign {
            write_executable(&tools.join("cosign"), "#!/bin/sh\nexit 0\n");
        }

        Self {
            _root: root,
            tools,
            artifacts,
            bin,
        }
    }

    fn run(&self, extra_arguments: &[&str]) -> std::process::Output {
        let mut command = Command::new("/bin/sh");
        command
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
            .args(["--version", "v-test", "--bin-dir"])
            .arg(&self.bin)
            .args(extra_arguments)
            .env("PATH", &self.tools)
            .env("POSTIL_TEST_ARTIFACTS", &self.artifacts)
            .env_remove("POSTIL_SKIP_SIG");
        command.output().unwrap()
    }
}

#[test]
fn require_cosign_fails_before_downloading_when_cosign_is_missing() {
    let output = Command::new("/bin/sh")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .arg("--require-cosign")
        .env("PATH", "/nonexistent")
        .env_remove("POSTIL_SKIP_SIG")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "install.sh: --require-cosign requires cosign in PATH\n"
    );
}

#[test]
fn checksum_only_installation_warns_that_publisher_identity_is_unverified() {
    let fixture = InstallerFixture::new(false);
    let output = fixture.run(&[]);

    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("the release signature was not verified"));
    assert!(stderr.contains("cannot prove who published the archive"));
    assert!(fixture.bin.join("postil").is_file());
}

#[test]
fn require_cosign_verifies_the_signature_before_installing() {
    let fixture = InstallerFixture::new(true);
    let output = fixture.run(&["--require-cosign"]);

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Signature verified (Sigstore keyless)."));
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("WARNING")
    );
    assert!(fixture.bin.join("postil").is_file());
}
