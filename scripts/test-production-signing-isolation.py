#!/usr/bin/env python3
import re
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
    require(publisher not in signing, "signing job must not receive publisher credentials")
    require(signer not in verification and publisher not in verification,
            "verification job must receive neither privileged adapter")
    require(publisher in publication, "publication job must receive the publisher adapter")
    require(signer not in publication, "publication job must not receive signing credentials")

    require("wedecent-update-signer" in signing, "signer must use its dedicated runner label")
    require("wedecent-update-verifier" in verification, "verifier must use its dedicated runner label")
    require("wedecent-release-publisher" in publication, "publisher must use its dedicated runner label")
    require("needs: publish-windows-downloads" in signing, "signer must wait for immutable artifacts")
    require("needs: sign-stable-update" in verification, "verifier must depend on signed candidate")
    require("needs: verify-stable-update" in publication, "publisher must depend on independent verification")

    sign_script = (ROOT / "scripts/sign-windows-stable-update.sh").read_text(encoding="utf-8")
    verify_script = (ROOT / "scripts/verify-windows-stable-update.sh").read_text(encoding="utf-8")
    publish_script = (ROOT / "scripts/publish-windows-stable-update-pair.sh").read_text(encoding="utf-8")
    require(signer in sign_script and publisher not in sign_script,
            "signing script must invoke only the signing adapter")
    require(signer not in verify_script and publisher not in verify_script,
            "verification script must have no signing or publication adapter")
    require(publisher in publish_script and signer not in publish_script,
            "publication script must invoke only the publication adapter")

    require("wedecent-stable-update-candidate-" in verification,
            "verification must consume the immutable signed-candidate artifact")
    require("wedecent-stable-update-verified-" in publication,
            "publication must consume the verifier-approved artifact")
    require("verification.receipt" in verification and "verification.receipt" in publication,
            "verifier receipt must bind candidate digests to publication")
    require("publish-windows-stable-update.sh" not in workflow,
            "production workflow must not invoke the legacy combined signing/publication script")

    print("Production signing/verifier/publisher privilege-boundary regression tests passed.")


if __name__ == "__main__":
    main()
