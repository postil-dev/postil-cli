#![cfg(any(target_os = "linux", target_os = "macos"))]

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

#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
const HOST_TARGET: &str = "x86_64-unknown-linux-gnu";
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "musl"))]
const HOST_TARGET: &str = "x86_64-unknown-linux-musl";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const MUSL_HOST_ARCH: &str = "x86_64";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const MUSL_HOST_TARGET: &str = "x86_64-unknown-linux-musl";
#[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "gnu"))]
const HOST_TARGET: &str = "aarch64-unknown-linux-gnu";
#[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "musl"))]
const HOST_TARGET: &str = "aarch64-unknown-linux-musl";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const MUSL_HOST_ARCH: &str = "aarch64";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const MUSL_HOST_TARGET: &str = "aarch64-unknown-linux-musl";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const HOST_TARGET: &str = "x86_64-apple-darwin";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const HOST_TARGET: &str = "aarch64-apple-darwin";

fn link_test_tools(tools: &Path) {
    for command in [
        "awk", "chmod", "cp", "grep", "gzip", "head", "ls", "mkdir", "mktemp", "mv", "rm", "tar",
        "uname",
    ] {
        symlink(system_command(command), tools.join(command)).unwrap();
    }

    #[cfg(target_os = "linux")]
    for command in ["ldd", "sha256sum"] {
        symlink(system_command(command), tools.join(command)).unwrap();
    }

    #[cfg(target_os = "macos")]
    symlink(system_command("shasum"), tools.join("shasum")).unwrap();
}

struct InstallerFixture {
    _root: tempfile::TempDir,
    tools: PathBuf,
    artifacts: PathBuf,
    bin: PathBuf,
    cosign_arguments: PathBuf,
}

impl InstallerFixture {
    fn new(with_cosign: bool) -> Self {
        Self::for_target(with_cosign, HOST_TARGET)
    }

    fn for_target(with_cosign: bool, target: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let tools = root.path().join("tools");
        let artifacts = root.path().join("artifacts");
        let payload = root.path().join("payload");
        let bin = root.path().join("bin");
        let cosign_arguments = root.path().join("cosign-arguments");
        for directory in [&tools, &artifacts, &payload, &bin] {
            fs::create_dir(directory).unwrap();
        }

        link_test_tools(&tools);

        write_executable(
            &payload.join("postil"),
            "#!/bin/sh\necho 'postil test-version'\n",
        );
        let archive_name = format!("postil-{target}.tar.gz");
        let archive = artifacts.join(&archive_name);
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
            artifacts.join(format!("{archive_name}.sha256")),
            format!("{digest}  {archive_name}\n"),
        )
        .unwrap();

        write_executable(
            &tools.join("curl"),
            &format!(
                "#!/bin/sh\ncase \"$2\" in\n  https://github.com/postil-dev/postil-cli/releases/download/v-test/{archive_name}.sha256) cp \"$POSTIL_TEST_ARTIFACTS/{archive_name}.sha256\" \"$4\" ;;\n  https://github.com/postil-dev/postil-cli/releases/download/v-test/{archive_name}.sig|https://github.com/postil-dev/postil-cli/releases/download/v-test/{archive_name}.pem) : > \"$4\" ;;\n  https://github.com/postil-dev/postil-cli/releases/download/v-test/{archive_name}) cp \"$POSTIL_TEST_ARTIFACTS/{archive_name}\" \"$4\" ;;\n  *) exit 1 ;;\nesac\n"
            ),
        );
        if with_cosign {
            write_executable(
                &tools.join("cosign"),
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$POSTIL_TEST_COSIGN_ARGS\"\n",
            );
        }

        Self {
            _root: root,
            tools,
            artifacts,
            bin,
            cosign_arguments,
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
            .env("POSTIL_TEST_COSIGN_ARGS", &self.cosign_arguments)
            .env_remove("POSTIL_SKIP_SIG");
        command.output().unwrap()
    }

    #[cfg(target_os = "linux")]
    fn simulate_musl_host(&self) {
        for command in ["uname", "ldd"] {
            fs::remove_file(self.tools.join(command)).unwrap();
        }
        write_executable(
            &self.tools.join("uname"),
            &format!(
                "#!/bin/sh\ncase \"$1\" in\n  -s) echo Linux ;;\n  -m) echo {MUSL_HOST_ARCH} ;;\n  *) exit 1 ;;\nesac\n"
            ),
        );
        write_executable(&self.tools.join("ldd"), "#!/bin/sh\necho 'musl libc'\n");
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
    assert!(stdout.contains("Next: run 'postil login', then run 'postil review' in a repository."));
    assert!(!stdout.contains("POSTIL_API_KEY"));
    let cosign_arguments = fs::read_to_string(&fixture.cosign_arguments).unwrap();
    assert!(cosign_arguments.contains(
        "--certificate-identity\nhttps://github.com/postil-dev/postil-cli/.github/workflows/release.yml@refs/tags/v-test\n"
    ));
    assert!(!cosign_arguments.contains("--certificate-identity-regexp"));
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("WARNING")
    );
    assert!(fixture.bin.join("postil").is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn musl_host_downloads_the_musl_release_asset() {
    let fixture = InstallerFixture::for_target(false, MUSL_HOST_TARGET);
    fixture.simulate_musl_host();
    let output = fixture.run(&[]);

    assert!(output.status.success(), "{output:?}");
    assert!(fixture.bin.join("postil").is_file());
}
