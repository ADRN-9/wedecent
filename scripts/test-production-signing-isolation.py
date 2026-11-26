#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile
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
    require(publisher in publication, "publication job must receive the publisher adapter")
    require("WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER_SHA256" in publication,
            "publisher adapter must be pinned by an independently configured digest")
    require(signer not in publication, "publication job must not receive signing credentials")

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
    require("WEDECENT_R2_CREATE_ONLY_UPLOADER" not in signing and "WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER" not in verification,
            "signer and verifier must not receive publication credentials")
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
    require(signer not in verify_script and publisher not in verify_script,
            "verification script must have no signing or publication adapter")
    require(publisher in publish_script and signer not in publish_script,
            "publication script must invoke only the publication adapter")
    require("WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER_SHA256" in publish_script and "sha256sum" in publish_script,
            "publication script must enforce the configured publisher digest pin")

    require("WEDECENT_R2_CREATE_ONLY_UPLOADER_SHA256" in publish_script,
            "publisher must pin the immutable keyset uploader executable")
    require("keysets/$epoch/keyset.json" in publish_script and "manifest-v2.json" in publish_script,
            "publisher must create immutable epoch keysets before the atomic v2 manifest pointer")
    require("verification.receipt" in publish_script and "keyset_sha256" in publish_script,
            "publisher must bind root-keyset bytes to the independent verifier receipt")
    require("WEDECENT_UPDATE_MANIFEST_SIGNER" not in publish_script,
            "publisher must not access signing credentials")
    require("WEDECENT_UPDATE_STABLE_PAIR_PUBLISHER" not in verify_script and "WEDECENT_R2_CREATE_ONLY_UPLOADER" not in verify_script,
            "verifier must not access publication credentials")

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
    # The signer receives a signing token only; the publisher receives a publish
    # token only. Cross-operations must fail closed.
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        sign_token = temp / "sign.token"
        publish_token = temp / "publish.token"
        sign_token.write_text("test-sign-only", encoding="utf-8")
        publish_token.write_text("test-publish-only", encoding="utf-8")
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
            "assert os.environ.get('PUBLISH_TOKEN') and not os.environ.get('SIGN_TOKEN')\n",
            encoding="utf-8",
        )
        signer_adapter.chmod(0o700)
        publisher_adapter.chmod(0o700)
        signer_env = {"PATH": os.environ.get("PATH", ""), "SIGN_TOKEN": str(sign_token)}
        publisher_env = {"PATH": os.environ.get("PATH", ""), "PUBLISH_TOKEN": str(publish_token)}
        require(subprocess.run([str(signer_adapter), "sign", "manifest"], env=signer_env, check=False).returncode == 0,
                "restricted signer credential must permit signing")
        require(subprocess.run([str(signer_adapter), "publish", "object"], env=signer_env, check=False).returncode != 0,
                "signer credential must not permit publication")
        require(subprocess.run([str(publisher_adapter), "publish"], env=publisher_env, check=False).returncode == 0,
                "restricted publisher credential must permit publication")
        require(subprocess.run([str(publisher_adapter), "sign"], env=publisher_env, check=False).returncode != 0,
                "publisher credential must not permit signing")

    print("Production signing/verifier/publisher privilege-boundary regression tests passed.")


if __name__ == "__main__":
    main()
