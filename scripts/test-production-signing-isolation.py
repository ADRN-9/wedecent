#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile
import uuid
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/production-release-build.yml"


def job_block(source: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        source,
    )
    if not match:
        raise AssertionError(f"missing production release job: {name}")
    return match.group(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    signing = job_block(workflow, "sign-stable-update")
    verification = job_block(workflow, "verify-stable-update")
    publication = job_block(workflow, "publish-stable-update")

    signer = "WEDECENT_UPDATE_MANIFEST_SIGNER"
    publisher = "WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER"

    require(signer in signing, "signing job must receive the signing adapter")
    require("WEDECENT_UPDATE_MANIFEST_SIGNER_SHA256" in signing,
            "signer adapter must be pinned by an independently configured digest")
    require(publisher not in signing, "signing job must not receive publisher credentials")
    require(signer not in verification and publisher not in verification,
            "verification job must receive neither privileged adapter")
    require("AWS_ACCESS_KEY_ID" in publication and "AWS_SECRET_ACCESS_KEY" in publication,
            "publication job must receive only the R2 write credential pair")
    require(signer not in publication, "publication job must not receive signing credentials")
    require("AWS_ACCESS_KEY_ID" not in signing and "AWS_SECRET_ACCESS_KEY" not in signing,
            "signing job must not receive R2 publication credentials")

    require("group: wedecent-update-signers" in signing, "signer must use its isolated runner group")
    require("group: wedecent-update-verifiers" in verification, "verifier must use its isolated runner group")
    require("group: wedecent-release-publishers" in publication, "publisher must use its isolated runner group")
    require("wedecent-update-signer" in signing, "signer must use its dedicated runner label")
    require("wedecent-update-verifier" in verification, "verifier must use its dedicated runner label")
    require("wedecent-release-publisher" in publication, "publisher must use its dedicated runner label")
    require("needs: publish-windows-downloads" in signing, "signer must wait for immutable artifacts")
    require("needs: sign-stable-update" in verification, "verifier must depend on signed candidate")
    require("needs: verify-stable-update" in publication, "publisher must depend on independent verification")
    require("id-token: write" in signing, "only signer workload may request an OIDC identity token")
    require("id-token: write" not in verification and "id-token: write" not in publication,
            "verification and publication workloads must not receive signer OIDC permission")

    require("WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH" in signing and "WEDECENT_UPDATE_KEYSET_PATH" in signing,
            "signer must use the provisioned root key and signed keyset")
    require("WEDECENT_UPDATE_ROOT_PUBLIC_KEY_PATH" in verification and "WEDECENT_UPDATE_KEYSET_PATH" not in verification,
            "verifier must consume candidate keyset but must not receive signer-side keyset path credentials")
    require("WEDECENT_R2_CREATE_ONLY_UPLOADER" not in signing and "AWS_ACCESS_KEY_ID" not in verification,
            "signer and verifier must not receive R2 publication credentials")
    require("manifest-v2.json" in verification and "manifest-v2.sig" in verification,
            "independent verifier must verify only schema-v2 stable manifests")
    require("manifest-v1.json" not in verification and "manifest-v1.sig" not in verification,
            "production verifier must not fall back to schema-v1 manifests")
    require("keysets/" in (ROOT / "internal/updateinfo/discovery.go").read_text(encoding="utf-8"),
            "stable discovery must resolve immutable epoch-specific keysets")
    require("VerifyManifestV2" in (ROOT / "internal/updateinfo/discovery.go").read_text(encoding="utf-8"),
            "stable discovery must use root-authorized v2 manifest verification")
    require("VerifyKeyset" in (ROOT / "internal/updateinfo/state.go").read_text(encoding="utf-8"),
            "protected update state must persist only root-verified keysets")

    sign_script = (ROOT / "scripts/sign-windows-stable-update.sh").read_text(encoding="utf-8")
    verify_script = (ROOT / "scripts/verify-windows-stable-update.sh").read_text(encoding="utf-8")
    publish_script = (ROOT / "scripts/publish-windows-stable-update-pair.sh").read_text(encoding="utf-8")
    require(signer in sign_script and publisher not in sign_script,
            "signing script must invoke only the signing adapter")
    require("WEDECENT_UPDATE_MANIFEST_SIGNER_SHA256" in sign_script and "sha256sum" in sign_script,
            "signing script must enforce the configured signer digest pin")
    require("--schema 2" in sign_script and "verify-v2" in sign_script,
            "production signer must explicitly create and verify schema-v2 manifests")
    require("verifier modified candidate manifest bytes" in verify_script and "verifier modified candidate signature bytes" in verify_script,
            "independent verifier must fail if signed input artifacts are modified")
    require(signer not in verify_script and publisher not in verify_script,
            "verification script must have no signing or publication adapter")
    require(signer not in publish_script and "AWS_ACCESS_KEY_ID" in publish_script,
            "publication script must use R2 publisher credentials and no signer")
    require("--if-match" in publish_script and "--if-none-match" in publish_script and "put-object" in publish_script,
            "publication script must use conditional R2 PutObject CAS")

    require("keysets/" in publish_script and "current-v2.json" in publish_script,
            "publisher must create immutable epoch keysets before the atomic v2 pair object")
    require("--receipt" in publish_script and "candidate_pair_sha256" in publish_script,
            "publisher must bind the single pair object to the independent verifier receipt")
    require("WEDECENT_UPDATE_MANIFEST_SIGNER" not in publish_script,
            "publisher must not access signing credentials")
    require("AWS_ACCESS_KEY_ID" not in verify_script and "AWS_SECRET_ACCESS_KEY" not in verify_script,
            "verifier must not access R2 publication credentials")

    require("wedecent-stable-update-candidate-" in verification,
            "verification must consume the immutable signed-candidate artifact")
    require("wedecent-stable-update-verified-" in publication,
            "publication must consume the verifier-approved artifact")
    require("verification.receipt" in verification and "verification.receipt" in publication,
            "verifier receipt must bind candidate digests to publication")
    require("publish-windows-stable-update.sh" not in workflow,
            "production workflow must not invoke the legacy combined signing/publication script")
    legacy_script = (ROOT / "scripts/publish-windows-stable-update.sh").read_text(encoding="utf-8")
    require('GITHUB_WORKFLOW:-' in legacy_script and 'Production release' in legacy_script,
            "legacy combined entrypoint must reject the production release workflow")

    # Test-only capability adapters model deliberately restricted credentials.
    # The signer receives a signing capability only; the publisher receives
    # R2 write credentials only. Cross-operations must fail closed.
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        sign_token = temp / "sign.token"
        publish_token = temp / "r2-write.token"
        sign_token.write_text("test-sign-only", encoding="utf-8")
        publish_token.write_text("test-r2-write-only", encoding="utf-8")
        sign_token.chmod(0o600)
        publish_token.chmod(0o600)
        signer_adapter = temp / "signer"
        publisher_adapter = temp / "publisher"
        signer_adapter.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            "assert len(sys.argv)==3 and sys.argv[1]=='sign'\n"
            "assert os.environ.get('SIGN_TOKEN') and not os.environ.get('PUBLISH_TOKEN')\n",
            encoding="utf-8",
        )
        publisher_adapter.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            "assert len(sys.argv)==2 and sys.argv[1]=='publish'\n"
            "assert os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY') and not os.environ.get('SIGN_TOKEN')\n",
            encoding="utf-8",
        )
        signer_adapter.chmod(0o700)
        publisher_adapter.chmod(0o700)
        signer_env = {"PATH": os.environ.get("PATH", ""), "SIGN_TOKEN": str(sign_token)}
        publisher_env = {"PATH": os.environ.get("PATH", ""), "AWS_ACCESS_KEY_ID": "test-access", "AWS_SECRET_ACCESS_KEY": str(publish_token)}
        require(subprocess.run([str(signer_adapter), "sign", "manifest"], env=signer_env, check=False).returncode == 0,
                "restricted signer credential must permit signing")
        require(subprocess.run([str(signer_adapter), "publish", "object"], env=signer_env, check=False, stderr=subprocess.DEVNULL).returncode != 0,
                "signer credential must not permit publication")
        require(subprocess.run([str(publisher_adapter), "publish"], env=publisher_env, check=False).returncode == 0,
                "restricted publisher credential must permit publication")
        require(subprocess.run([str(publisher_adapter), "sign"], env=publisher_env, check=False, stderr=subprocess.DEVNULL).returncode != 0,
                "publisher credential must not permit signing")

    # Exercise the same boundary with two real, distinct ephemeral Linux UIDs
    # and 0600 credential files. This proves the test runner's OS permission
    # model, not the production self-hosted runner inventory.
    sudo = shutil.which("sudo")
    if sudo and subprocess.run([sudo, "-n", "true"], check=False).returncode == 0:
        suffix = uuid.uuid4().hex[:10]
        signer_user = "wdsgn" + suffix
        publisher_user = "wdpub" + suffix
        created_users = []
        try:
            for username in (signer_user, publisher_user):
                subprocess.run(
                    [sudo, "-n", "useradd", "--system", "--user-group", "--no-create-home",
                     "--shell", "/usr/sbin/nologin", username],
                    check=True,
                )
                created_users.append(username)
            with tempfile.TemporaryDirectory() as temporary:
                os.chmod(temporary, 0o755)
                temp = Path(temporary)
                signer_dir = temp / "signer"
                publisher_dir = temp / "publisher"
                signer_dir.mkdir(mode=0o700)
                publisher_dir.mkdir(mode=0o700)
                signer_secret = signer_dir / "ed25519-signing-key"
                publisher_secret = publisher_dir / "r2-publisher-key"
                signer_secret.write_text("test-only-ed25519-secret", encoding="utf-8")
                publisher_secret.write_text("test-only-r2-publisher-secret", encoding="utf-8")
                signer_secret.chmod(0o600)
                publisher_secret.chmod(0o600)
                subprocess.run([sudo, "-n", "chown", "-R", f"{signer_user}:{signer_user}", str(signer_dir)], check=True)
                subprocess.run([sudo, "-n", "chown", "-R", f"{publisher_user}:{publisher_user}", str(publisher_dir)], check=True)
                probe = (
                    "import sys\n"
                    "op, own, other = sys.argv[1:]\n"
                    "open(own, 'r', encoding='utf-8').read()\n"
                    "try:\n"
                    "    open(other, 'r', encoding='utf-8').read()\n"
                    "except (PermissionError, FileNotFoundError):\n"
                    "    pass\n"
                    "else:\n"
                    "    raise SystemExit('cross-role credential unexpectedly readable')\n"
                    "assert op in ('sign', 'publish')\n"
                )
                def as_user(username, operation, own, other):
                    return subprocess.run(
                        [sudo, "-n", "-u", username, "--", "python3", "-c", probe,
                         operation, str(own), str(other)],
                        check=False,
                    ).returncode
                try:
                    require(as_user(signer_user, "sign", signer_secret, publisher_secret) == 0,
                            "signer OS account must read its own key and not publisher credentials")
                    require(as_user(publisher_user, "publish", publisher_secret, signer_secret) == 0,
                            "publisher OS account must read its own credential and not signer key")
                    require(as_user(signer_user, "publish", publisher_secret, signer_secret) != 0,
                            "signer OS account must be unable to publish")
                    require(as_user(publisher_user, "sign", signer_secret, publisher_secret) != 0,
                finally:
                    # Restore ownership so the invoking runner can remove the temporary tree.
                    subprocess.run([sudo, "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(temp)], check=True)
                        "publisher OS account must be unable to sign")
        finally:
            for username in reversed(created_users):
                subprocess.run([sudo, "-n", "userdel", username], check=False)
    else:
        require(not os.environ.get("CI"), "CI runner must support sudo for distinct-UID credential isolation tests")

    print("Production signing/verifier/publisher privilege-boundary regression tests passed.")


if __name__ == "__main__":
    main()
