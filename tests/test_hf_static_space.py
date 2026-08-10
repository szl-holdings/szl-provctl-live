from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "hf_static_space.py"
SPEC = importlib.util.spec_from_file_location("hf_static_space", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SOURCE_SHA = "a" * 40
PARENT_SHA = "b" * 40
TARGET_SHA = "c" * 40
PR_HEAD_SHA = "d" * 40
RELEASE_RUN_ID = 98
BOUNDARY_RUN_ID = 99


def governed_merge_evidence(source_sha: str = SOURCE_SHA) -> dict:
    repository = MODULE.load_config()["source_repository"]
    return {
        "schema": "szl.github-governed-merge/v2",
        "status": "AUTHORIZED_EXACT_GOVERNED_MERGE",
        "source_revision": source_sha,
        "repository": {
            "default_branch": "main",
            "full_name": repository,
            "id": MODULE.TARGET_REPOSITORY_IDS[repository],
        },
        "push": {"before": PARENT_SHA, "after": source_sha},
        "pull_request": {
            "base_revision": PARENT_SHA,
            "head_ref": "release-candidate",
            "head_revision": PR_HEAD_SHA,
            "merge_revision": source_sha,
            "merged_at": "2026-08-10T00:00:00Z",
            "merged_by": "solo-owner",
            "number": 7,
        },
        "required_checks": [
            {
                "app_id": MODULE.GITHUB_ACTIONS_INTEGRATION_ID,
                "check_run_id": index + 10,
                "conclusion": "success",
                "head_revision": PR_HEAD_SHA,
                "name": name,
                "workflow_run_id": RELEASE_RUN_ID,
            }
            for index, name in enumerate(sorted(MODULE.REQUIRED_STATUS_CONTEXTS))
        ],
        "release_workflow": {
            "base_revision": PARENT_SHA,
            "conclusion": "success",
            "event": "pull_request",
            "head_ref": "release-candidate",
            "head_revision": PR_HEAD_SHA,
            "name": MODULE.RELEASE_WORKFLOW_NAME,
            "path": MODULE.RELEASE_WORKFLOW_PATH,
            "pull_request_number": 7,
            "repository_id": MODULE.TARGET_REPOSITORY_IDS[repository],
            "run_attempt": 1,
            "run_id": RELEASE_RUN_ID,
            "status": "completed",
            "workflow_id": MODULE.TARGET_RELEASE_WORKFLOW_IDS[repository],
        },
        "required_workflow": {
            "base_revision": PARENT_SHA,
            "conclusion": "success",
            "event": "pull_request",
            "head_ref": "release-candidate",
            "head_revision": PR_HEAD_SHA,
            "name": MODULE.REQUIRED_WORKFLOW_NAME,
            "path": MODULE.REQUIRED_WORKFLOW_PATH,
            "pull_request_number": 7,
            "repository_id": MODULE.TARGET_REPOSITORY_IDS[repository],
            "run_attempt": 1,
            "run_id": BOUNDARY_RUN_ID,
            "status": "completed",
            "workflow_id": MODULE.TARGET_REQUIRED_WORKFLOW_IDS[repository],
        },
    }


def write_authorization(root: Path, source_sha: str = SOURCE_SHA) -> Path:
    path = root / "governed-merge.json"
    path.write_bytes(MODULE.canonical_json(governed_merge_evidence(source_sha)))
    return path


def write_push_event(path: Path, source_sha: str = SOURCE_SHA) -> None:
    repository = MODULE.load_config()["source_repository"]
    repository_id = MODULE.TARGET_REPOSITORY_IDS[repository]
    path.write_text(
        json.dumps(
            {
                "before": PARENT_SHA,
                "after": source_sha,
                "ref": "refs/heads/main",
                "repository": {
                    "id": repository_id,
                    "full_name": repository,
                    "default_branch": "main",
                },
            }
        ),
        encoding="utf-8",
    )


def guard_responder(
    *,
    boundary_conclusion: str = "success",
    check_app_id: int = 15368,
    release_conclusion: str = "success",
    stale_boundary_success: bool = False,
    stale_check_success: bool = False,
    misbound_boundary: bool = False,
):
    repository = MODULE.load_config()["source_repository"]
    repository_id = MODULE.TARGET_REPOSITORY_IDS[repository]
    pull = {
        "id": 70,
        "number": 7,
        "state": "closed",
        "merged": True,
        "merged_at": "2026-08-10T00:00:00Z",
        "merge_commit_sha": SOURCE_SHA,
        "merged_by": {"login": "solo-owner"},
        "base": {
            "ref": "main",
            "sha": PARENT_SHA,
            "repo": {"full_name": repository, "id": repository_id},
        },
        "head": {
            "ref": "release-candidate",
            "sha": PR_HEAD_SHA,
            "repo": {"full_name": repository, "id": repository_id},
        },
    }

    def run_pull(number: int = 7) -> dict:
        return {
            "number": number,
            "head": {
                "ref": "release-candidate",
                "sha": PR_HEAD_SHA,
                "repo": {"id": repository_id},
            },
            "base": {
                "ref": "main",
                "sha": PARENT_SHA,
                "repo": {"id": repository_id},
            },
        }

    def workflow_run(
        run_id: int,
        workflow_id: int,
        name: str,
        path: str,
        conclusion: str,
        *,
        pull_number: int = 7,
    ) -> dict:
        return {
            "id": run_id,
            "workflow_id": workflow_id,
            "name": name,
            "path": path,
            "event": "pull_request",
            "head_sha": PR_HEAD_SHA,
            "status": "completed",
            "conclusion": conclusion,
            "run_attempt": 1,
            "repository": {"full_name": repository, "id": repository_id},
            "pull_requests": [run_pull(pull_number)],
        }

    def respond(url: str, token: str = "") -> object:
        if token != "github-test-token":
            raise AssertionError("guard omitted its GitHub credential")
        if url.endswith(f"/repos/{repository}"):
            return {
                "id": repository_id,
                "full_name": repository,
                "default_branch": "main",
            }
        if url.endswith(f"/repos/{repository}/branches/main"):
            return {"commit": {"sha": SOURCE_SHA}}
        if url.endswith(f"/repos/{repository}/commits/{SOURCE_SHA}/pulls"):
            return [pull]
        if url.endswith(f"/repos/{repository}/pulls/7"):
            return pull
        if f"/repos/{repository}/actions/runs?" in url:
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            if query.get("head_sha") != [PR_HEAD_SHA] or query.get("event") != [
                "pull_request"
            ]:
                raise AssertionError("workflow query is not exact")
            runs = [
                workflow_run(
                    RELEASE_RUN_ID,
                    MODULE.TARGET_RELEASE_WORKFLOW_IDS[repository],
                    MODULE.RELEASE_WORKFLOW_NAME,
                    MODULE.RELEASE_WORKFLOW_PATH,
                    release_conclusion,
                )
            ]
            if stale_boundary_success:
                runs.append(
                    workflow_run(
                        BOUNDARY_RUN_ID,
                        MODULE.TARGET_REQUIRED_WORKFLOW_IDS[repository],
                        MODULE.REQUIRED_WORKFLOW_NAME,
                        MODULE.REQUIRED_WORKFLOW_PATH,
                        "success",
                    )
                )
                boundary_run_id = BOUNDARY_RUN_ID + 100
            else:
                boundary_run_id = BOUNDARY_RUN_ID
            runs.append(
                workflow_run(
                    boundary_run_id,
                    MODULE.TARGET_REQUIRED_WORKFLOW_IDS[repository],
                    MODULE.REQUIRED_WORKFLOW_NAME,
                    MODULE.REQUIRED_WORKFLOW_PATH,
                    boundary_conclusion,
                    pull_number=8 if misbound_boundary else 7,
                )
            )
            return {"total_count": len(runs), "workflow_runs": runs}
        if url.endswith(
            f"/repos/{repository}/commits/{PR_HEAD_SHA}/check-runs?per_page=100"
        ):
            checks = []
            for index, name in enumerate(sorted(MODULE.REQUIRED_STATUS_CONTEXTS)):
                check_id = index + 10
                checks.append(
                    {
                        "id": check_id,
                        "name": name,
                        "head_sha": PR_HEAD_SHA,
                        "status": "completed",
                        "conclusion": "success",
                        "app": {"id": check_app_id},
                        "details_url": (
                            f"https://github.com/{repository}/actions/runs/"
                            f"{RELEASE_RUN_ID}/job/{check_id}"
                        ),
                    }
                )
                if stale_check_success:
                    latest_id = check_id + 100
                    checks.append(
                        {
                            "id": latest_id,
                            "name": name,
                            "head_sha": PR_HEAD_SHA,
                            "status": "completed",
                            "conclusion": "failure",
                            "app": {"id": check_app_id},
                            "details_url": (
                                f"https://github.com/{repository}/actions/runs/"
                                f"{RELEASE_RUN_ID}/job/{latest_id}"
                            ),
                        }
                    )
            return {"total_count": len(checks), "check_runs": checks}
        raise AssertionError(f"unexpected guard URL: {url}")

    return respond


class FakeHfApi:
    def __init__(self, stale: bool = False, events: list[str] | None = None) -> None:
        self.stale = stale
        self.events = events if events is not None else []
        self.upload_kwargs: dict | None = None

    def space_info(self, target: str, token: str, timeout: float):
        if timeout <= 0 or timeout > MODULE.HF_REQUEST_TIMEOUT_CAP:
            raise AssertionError("parent lookup timeout was not strictly capped")
        self.events.append("parent")
        return SimpleNamespace(sha=PARENT_SHA)

    def upload_folder(self, **kwargs):
        self.events.append("upload")
        self.upload_kwargs = kwargs
        if self.stale:
            raise RuntimeError("parent commit changed")
        return SimpleNamespace(oid=TARGET_SHA)


def live_tree(bundle: Path) -> list[dict]:
    rows = []
    for path in sorted(item for item in bundle.rglob("*") if item.is_file()):
        data = path.read_bytes()
        rows.append(
            {
                "path": path.relative_to(bundle).as_posix(),
                "type": "file",
                "oid": MODULE.git_blob_sha1(data),
                "size": len(data),
            }
        )
    return rows


def write_deploy_result(bundle: Path, result_path: Path) -> dict:
    manifest = MODULE.validate_bundle(bundle, SOURCE_SHA)
    result = {
        "schema": "szl.hf-deploy-result/v1",
        "status": "PUBLISHED_AWAITING_ATTESTATION",
        "source_revision": SOURCE_SHA,
        "previous_hf_revision": PARENT_SHA,
        "hf_revision": TARGET_SHA,
        "bundle_sha256": manifest["bundle_sha256"],
        "target": MODULE.load_config()["target"],
        "upload_transport": "RETURNED_AUTHORITATIVE_REVISION",
        "authorization": governed_merge_evidence(),
    }
    result_path.write_bytes(MODULE.canonical_json(result))
    return result


class StaticSpaceContractTests(unittest.TestCase):
    def test_bundle_is_closed_and_source_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            manifest = MODULE.build_bundle(output, SOURCE_SHA)
            self.assertEqual(manifest["source_revision"], SOURCE_SHA)
            self.assertEqual(manifest["schema"], "szl.hf-deploy-manifest/v3")
            self.assertEqual(MODULE.validate_bundle(output, SOURCE_SHA), manifest)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "LICENSE",
                    "README.md",
                    "SPACE_PROVENANCE.json",
                    "hf-deploy-manifest.json",
                    "index.html",
                },
            )
            provenance = json.loads((output / "SPACE_PROVENANCE.json").read_text())
            self.assertEqual(provenance["source"]["revision"], SOURCE_SHA)
            self.assertEqual(provenance["target"]["sdk"], "static")

    def test_bundle_rejects_tampering_and_mutable_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            MODULE.build_bundle(output, SOURCE_SHA)
            (output / "index.html").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.ContractError, "bundle (byte count|digest) mismatch"):
                MODULE.validate_bundle(output, SOURCE_SHA)
            for revision in ("main", "a" * 12, "G" * 40):
                with self.subTest(revision=revision):
                    with self.assertRaises(MODULE.ContractError):
                        MODULE.build_bundle(Path(temporary) / revision, revision)

    def test_space_card_is_static_and_source_controlled(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertTrue(readme.startswith("---\n"))
        front_matter = readme.split("\n---\n", 1)[0]
        self.assertIn("sdk: static", front_matter)
        self.assertIn("app_file: index.html", front_matter)

    def test_publisher_lock_is_exact_and_hash_closed(self) -> None:
        lock = ROOT / "requirements" / "hf-publisher.lock"
        pattern = re.compile(
            r"^([A-Za-z0-9_.-]+)==([^\s]+) --hash=sha256:([0-9a-f]{64})$"
        )
        packages: dict[str, str] = {}
        for line in lock.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            match = pattern.fullmatch(line)
            self.assertIsNotNone(match, line)
            assert match
            name, version, _ = match.groups()
            normalized = name.lower().replace("_", "-")
            self.assertNotIn(normalized, packages)
            packages[normalized] = version
        self.assertEqual(packages["huggingface-hub"], "1.19.0")
        self.assertGreaterEqual(len(packages), 20)

    def test_validator_lock_is_minimal_cross_platform_and_hash_closed(self) -> None:
        lock = (ROOT / "requirements" / "hf-validator.lock").read_text(
            encoding="utf-8"
        )
        requirements = re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^\s\\]+)", lock)
        hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", lock))
        self.assertEqual(requirements, [("PyYAML", "6.0.3")])
        self.assertEqual(
            hashes,
            {
                "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc",
                "5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b",
            },
        )

    def test_repository_identity_is_one_exact_governed_target(self) -> None:
        config = MODULE.load_config()
        expected = {
            "szl-holdings/lambda-gate-holo": 1295931629,
            "szl-holdings/governed-norm-holo": 1295931607,
            "szl-holdings/energy-attest-holo": 1295929955,
            "szl-holdings/receipt-chain-live": 1295940016,
            "szl-holdings/szl-provctl-live": 1295941247,
        }
        self.assertEqual(MODULE.TARGET_REPOSITORY_IDS, expected)
        self.assertIn(config["source_repository"], expected)
        self.assertEqual(
            config["target"],
            "SZLHOLDINGS/" + config["source_repository"].split("/", 1)[1],
        )

    def test_guard_authorizes_exact_governed_merge(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            output_path = root / "governed-merge.json"
            failure_path = root / "governed-merge-failure.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    MODULE, "_request_json", side_effect=guard_responder()
                ):
                    result = MODULE.require_governed_main(
                        SOURCE_SHA,
                        event_path,
                        output_path,
                        failure_output_path=failure_path,
                    )
            self.assertEqual(result["status"], "AUTHORIZED_EXACT_GOVERNED_MERGE")
            self.assertEqual(result["push"], {"before": PARENT_SHA, "after": SOURCE_SHA})
            self.assertEqual(result["pull_request"]["head_revision"], PR_HEAD_SHA)
            self.assertEqual(
                result["required_workflow"]["workflow_id"],
                MODULE.TARGET_REQUIRED_WORKFLOW_IDS[repository],
            )
            self.assertEqual(
                result["release_workflow"]["workflow_id"],
                MODULE.TARGET_RELEASE_WORKFLOW_IDS[repository],
            )
            self.assertEqual(output_path.read_bytes(), MODULE.canonical_json(result))
            self.assertFalse(failure_path.exists())

    def test_guard_rejects_direct_push_and_spoofed_required_evidence(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            write_push_event(event_path)
            variants = [
                (
                    "failed boundary",
                    guard_responder(boundary_conclusion="failure"),
                    "latest exact required release-boundary workflow",
                ),
                (
                    "stale boundary success",
                    guard_responder(
                        boundary_conclusion="failure", stale_boundary_success=True
                    ),
                    "latest exact required release-boundary workflow",
                ),
                (
                    "stale check success",
                    guard_responder(stale_check_success=True),
                    "latest exact publisher-workflow check",
                ),
                (
                    "misbound boundary",
                    guard_responder(misbound_boundary=True),
                    "pull-request tuple is not exact",
                ),
                (
                    "failed publisher workflow",
                    guard_responder(release_conclusion="failure"),
                    "latest exact publisher workflow",
                ),
                (
                    "wrong check app",
                    guard_responder(check_app_id=99),
                    "required exact publisher-workflow check",
                ),
            ]
            with mock.patch.dict(os.environ, environment, clear=False):
                for label, responder, diagnostic in variants:
                    with self.subTest(label=label):
                        with mock.patch.object(
                            MODULE, "_request_json", side_effect=responder
                        ):
                            with self.assertRaisesRegex(MODULE.ContractError, diagnostic):
                                MODULE.require_governed_main(
                                    SOURCE_SHA,
                                    event_path,
                                    root / f"{label}.json",
                                    failure_output_path=root / f"{label}-failure.json",
                                )
            direct_event = json.loads(event_path.read_text(encoding="utf-8"))
            direct_event["before"] = "e" * 40
            event_path.write_text(json.dumps(direct_event), encoding="utf-8")
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    MODULE, "_request_json", side_effect=guard_responder()
                ):
                    with self.assertRaisesRegex(MODULE.ContractError, "unambiguous merged PR"):
                        MODULE.require_governed_main(
                            SOURCE_SHA,
                            event_path,
                            root / "direct.json",
                            failure_output_path=root / "direct-failure.json",
                        )

    def test_governed_merge_evidence_is_canonical_and_source_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authorization = write_authorization(root)
            loaded = MODULE.load_governed_merge(authorization, SOURCE_SHA)
            self.assertEqual(loaded, governed_merge_evidence())
            authorization.write_text(
                json.dumps(governed_merge_evidence(), indent=2), encoding="utf-8"
            )
            with self.assertRaisesRegex(MODULE.ContractError, "not canonical"):
                MODULE.load_governed_merge(authorization, SOURCE_SHA)
            authorization.write_bytes(
                MODULE.canonical_json(governed_merge_evidence(TARGET_SHA))
            )
            with self.assertRaisesRegex(MODULE.ContractError, "not bound"):
                MODULE.load_governed_merge(authorization, SOURCE_SHA)

    def test_guard_api_error_fails_closed(self) -> None:
        with mock.patch.object(
            MODULE.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ):
            with self.assertRaisesRegex(MODULE.ContractError, "JSON request failed closed"):
                MODULE._request_json("https://api.github.test/repos/example/repo", "token")

    def test_guard_missing_token_fails_closed_before_api(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(MODULE, "_request_json") as request_json:
                    with self.assertRaisesRegex(
                        MODULE.ContractError, "GITHUB_TOKEN is required"
                    ):
                        MODULE.require_governed_main(
                            SOURCE_SHA, event_path, root / "authorization.json"
                        )
            request_json.assert_not_called()

    def test_dco_validates_every_commit_with_matching_trailer(self) -> None:
        commits = ["1" * 40, "2" * 40]
        messages = {
            commits[0]: (
                "Lutar, Stephen P.\0stephenlutar2@gmail.com\0"
                "Lutar, Stephen P.\0stephenlutar2@gmail.com\0"
                "feat: first\n\nSigned-off-by: Lutar, Stephen P. <stephenlutar2@gmail.com>\n"
            ),
            commits[1]: (
                "Lutar, Stephen P.\0stephenlutar2@gmail.com\0"
                "Lutar, Stephen P.\0stephenlutar2@gmail.com\0"
                "fix: second\n\nSigned-off-by: Lutar, Stephen P. <stephenlutar2@gmail.com>\n"
            ),
        }

        def git_output(arguments: list[str]) -> str:
            if arguments[:2] == ["merge-base", "--is-ancestor"]:
                return ""
            if arguments[:2] == ["rev-list", "--reverse"]:
                return "\n".join(commits) + "\n"
            if arguments[0] == "show":
                return messages[arguments[-1]]
            raise AssertionError(arguments)

        with mock.patch.object(MODULE, "_git_output", side_effect=git_output):
            result = MODULE.validate_dco_range(SOURCE_SHA, TARGET_SHA)
        self.assertEqual(result["status"], "DCO_VALID")
        self.assertEqual(result["commits"], commits)
        self.assertEqual(result["commit_count"], 2)

    def test_dco_rejects_any_commit_without_matching_trailer(self) -> None:
        commits = ["1" * 40, "2" * 40]

        def git_output(arguments: list[str]) -> str:
            if arguments[:2] == ["merge-base", "--is-ancestor"]:
                return ""
            if arguments[:2] == ["rev-list", "--reverse"]:
                return "\n".join(commits) + "\n"
            if arguments[0] == "show":
                message = "fix: unsigned\n"
                if arguments[-1] == commits[0]:
                    message += (
                        "\nSigned-off-by: Lutar, Stephen P. "
                        "<stephenlutar2@gmail.com>\n"
                    )
                return (
                    "Lutar, Stephen P.\0stephenlutar2@gmail.com\0"
                    "Lutar, Stephen P.\0stephenlutar2@gmail.com\0"
                    + message
                )
            raise AssertionError(arguments)

        with mock.patch.object(MODULE, "_git_output", side_effect=git_output):
            with self.assertRaisesRegex(MODULE.ContractError, commits[1]):
                MODULE.validate_dco_range(SOURCE_SHA, TARGET_SHA)

    def test_workflow_exposes_stable_dco_and_exact_python(self) -> None:
        workflow_path = ROOT / ".github" / "workflows" / "hf-static-space.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        document = yaml.safe_load(workflow)
        jobs = document["jobs"]
        validate_text = json.dumps(jobs["validate"], sort_keys=True)
        self.assertEqual(jobs["dco"]["name"], "DCO")
        self.assertEqual(jobs["validate"]["name"], "validate-static-space")
        self.assertEqual(jobs["authorize"]["needs"], ["validate", "dco"])
        self.assertEqual(
            jobs["authorize"]["permissions"],
            {
                "actions": "read",
                "checks": "read",
                "contents": "read",
                "pull-requests": "read",
            },
        )
        self.assertEqual(jobs["deploy"]["permissions"], {})
        self.assertEqual(
            jobs["attest"]["permissions"],
            {"attestations": "write", "contents": "read", "id-token": "write"},
        )
        self.assertEqual(
            jobs["attest"]["if"],
            "always() && github.event_name == 'push' && github.ref == 'refs/heads/main'",
        )
        authorize_text = json.dumps(jobs["authorize"], sort_keys=True)
        deploy_text = json.dumps(jobs["deploy"], sort_keys=True)
        measure_text = json.dumps(jobs["measure"], sort_keys=True)
        attest_text = json.dumps(jobs["attest"], sort_keys=True)
        self.assertNotIn("HF_TOKEN", authorize_text)
        self.assertIn("requirements/hf-validator.lock", validate_text)
        self.assertNotIn("requirements/hf-publisher.lock", validate_text)
        self.assertNotIn("huggingface_hub", validate_text)
        self.assertNotIn("${{ github.token }}", deploy_text)
        self.assertIn('"GITHUB_TOKEN": ""', deploy_text)
        self.assertIn('"HF_TOKEN": "${{ secrets.HF_TOKEN }}"', deploy_text)
        self.assertIn('"HF_TOKEN": ""', measure_text)
        self.assertIn('"GITHUB_TOKEN": "${{ github.token }}"', measure_text)
        self.assertNotIn("secrets.HF_TOKEN", attest_text)
        self.assertIn('"GITHUB_TOKEN": ""', attest_text)
        self.assertNotIn("actions/create-github-app-token@", workflow)
        self.assertNotIn("QILLQAQ", workflow)
        self.assertNotIn("permission-administration", workflow)
        self.assertNotIn("--dry-run", workflow)
        self.assertEqual(workflow.count("HF_TOKEN: ${{ secrets.HF_TOKEN }}"), 1)
        self.assertEqual(workflow.count("id-token: write"), 1)
        self.assertEqual(workflow.count("attestations: write"), 1)
        self.assertGreaterEqual(
            workflow.count("--require-hashes --only-binary=:all: --ignore-installed"),
            2,
        )
        self.assertIn("--authorization-outcome", workflow)
        self.assertIn("--publisher-environment-outcome", workflow)
        self.assertIn("--publisher-evidence-outcome", workflow)
        self.assertIn("--authorization", workflow)
        self.assertIn("--authorization-output", workflow)
        self.assertIn("Require terminal governed success", workflow)
        self.assertIn(
            "actions/attest-build-provenance@"
            "a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32",
            workflow,
        )

    def test_deploy_uses_parent_lock_and_full_tree_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            failure_path = root / "failure.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            events: list[str] = []
            api = FakeHfApi(events=events)
            fake_hub = SimpleNamespace(HfApi=lambda token: api)

            with mock.patch.dict(
                os.environ, {"HF_TOKEN": "test-token"}, clear=False
            ), mock.patch.dict(
                sys.modules, {"huggingface_hub": fake_hub}
            ), mock.patch.object(
                MODULE, "_require_strict_mutation_timer"
            ), mock.patch.object(
                MODULE,
                "_run_with_wall_clock_deadline",
                side_effect=lambda action, _deadline, _label: action(),
            ):
                result = MODULE.deploy_bundle(
                    bundle,
                    SOURCE_SHA,
                    result_path,
                    authorization_path=authorization_path,
                    failure_output_path=failure_path,
                )
            assert api.upload_kwargs is not None
            self.assertEqual(api.upload_kwargs["parent_commit"], PARENT_SHA)
            self.assertEqual(api.upload_kwargs["delete_patterns"], "*")
            self.assertEqual(Path(api.upload_kwargs["folder_path"]), bundle)
            self.assertEqual(result["previous_hf_revision"], PARENT_SHA)
            self.assertEqual(result["hf_revision"], TARGET_SHA)
            self.assertEqual(events, ["parent", "upload"])
            self.assertEqual(result["authorization"], governed_merge_evidence())
            self.assertFalse(failure_path.exists())

    def test_deploy_stale_parent_fails_without_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            failure_path = root / "failure.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            api = FakeHfApi(stale=True)
            fake_hub = SimpleNamespace(HfApi=lambda token: api)
            with mock.patch.dict(
                os.environ, {"HF_TOKEN": "test-token"}, clear=False
            ), mock.patch.dict(
                sys.modules, {"huggingface_hub": fake_hub}
            ), mock.patch.object(
                MODULE, "_require_strict_mutation_timer"
            ), mock.patch.object(
                MODULE,
                "_run_with_wall_clock_deadline",
                side_effect=lambda action, _deadline, _label: action(),
            ), mock.patch.object(
                MODULE,
                "_recover_authoritative_revision",
                side_effect=MODULE.ContractError("no authoritative revision"),
            ):
                with self.assertRaisesRegex(
                    MODULE.ContractError,
                    "canonical machine-readable evidence was persisted",
                ):
                    MODULE.deploy_bundle(
                        bundle,
                        SOURCE_SHA,
                        result_path,
                        authorization_path=authorization_path,
                        failure_output_path=failure_path,
                    )
            self.assertFalse(result_path.exists())
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(failure["status"], "MUTATION_OUTCOME_UNKNOWN")
            self.assertTrue(failure["upload_call_entered"])
            self.assertIsNone(failure["hf_revision"])
            self.assertFalse(failure["receipt_minted"])
            self.assertFalse(failure["deployment_success"])
            self.assertEqual(failure_path.read_bytes(), MODULE.canonical_json(failure))

    def test_deploy_requires_evidence_path_at_call_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(TypeError, "authorization_path"):
                MODULE.deploy_bundle(root / "bundle", SOURCE_SHA, root / "result.json")

    def test_pre_mutation_failure_writes_canonical_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            failure_path = root / "failure.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(
                    MODULE.ContractError,
                    "canonical machine-readable evidence was persisted",
                ):
                    MODULE.deploy_bundle(
                        bundle,
                        SOURCE_SHA,
                        result_path,
                        authorization_path=authorization_path,
                        failure_output_path=failure_path,
                    )
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(failure["status"], "FAILED_BEFORE_MUTATION")
            self.assertFalse(failure["upload_call_entered"])
            self.assertIsNone(failure["hf_revision"])
            self.assertFalse(failure["receipt_minted"])
            self.assertFalse(failure["deployment_success"])
            self.assertEqual(failure_path.read_bytes(), MODULE.canonical_json(failure))
            self.assertFalse(result_path.exists())

    def test_known_revision_failure_writes_partial_after_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result-directory"
            failure_path = root / "failure.json"
            result_path.mkdir()
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            api = FakeHfApi()
            fake_hub = SimpleNamespace(HfApi=lambda token: api)
            with mock.patch.dict(
                os.environ, {"HF_TOKEN": "test-token"}, clear=False
            ), mock.patch.dict(
                sys.modules, {"huggingface_hub": fake_hub}
            ), mock.patch.object(
                MODULE, "_require_strict_mutation_timer"
            ), mock.patch.object(
                MODULE,
                "_run_with_wall_clock_deadline",
                side_effect=lambda action, _deadline, _label: action(),
            ):
                with self.assertRaisesRegex(
                    MODULE.ContractError,
                    "canonical machine-readable evidence was persisted",
                ):
                    MODULE.deploy_bundle(
                        bundle,
                        SOURCE_SHA,
                        result_path,
                        authorization_path=authorization_path,
                        failure_output_path=failure_path,
                    )
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(failure["status"], "PARTIAL_AFTER_MUTATION")
            self.assertTrue(failure["upload_call_entered"])
            self.assertEqual(failure["hf_revision"], TARGET_SHA)
            self.assertFalse(failure["receipt_minted"])
            self.assertFalse(failure["deployment_success"])
            self.assertEqual(failure_path.read_bytes(), MODULE.canonical_json(failure))

    def test_evidence_write_failure_is_terminal_and_truthful(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            failure_path = root / "failure.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                MODULE,
                "_write_mutation_failure",
                side_effect=OSError("disk full token=raw-secret"),
            ):
                with self.assertRaises(MODULE.ContractError) as raised:
                    MODULE.deploy_bundle(
                        bundle,
                        SOURCE_SHA,
                        result_path,
                        authorization_path=authorization_path,
                        failure_output_path=failure_path,
                    )
            message = str(raised.exception)
            self.assertIn("mandatory machine-readable evidence could not be persisted", message)
            self.assertNotIn("was persisted", message)
            self.assertNotIn("raw-secret", message)
            self.assertIn("<redacted>", message)
            self.assertFalse(failure_path.exists())
            self.assertFalse(result_path.exists())

    def test_live_tree_requires_exact_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            exact = live_tree(bundle)
            self.assertEqual(
                MODULE.verify_live_tree(bundle, exact, [".gitattributes"]), len(exact)
            )
            unmanaged = copy.deepcopy(exact)
            unmanaged.append(
                {"path": "stale.txt", "type": "file", "oid": "d" * 40, "size": 1}
            )
            with self.assertRaisesRegex(MODULE.ContractError, "unmanaged files"):
                MODULE.verify_live_tree(bundle, unmanaged, [".gitattributes"])
            wrong = copy.deepcopy(exact)
            index = next(row for row in wrong if row["path"] == "index.html")
            index["oid"] = "e" * 40
            with self.assertRaisesRegex(MODULE.ContractError, "live Space bytes differ"):
                MODULE.verify_live_tree(bundle, wrong, [".gitattributes"])

    def test_static_redirect_and_exact_public_index(self) -> None:
        origin = "https://szlholdings-example.static.hf.space"
        query = urllib.parse.urlencode({"source": SOURCE_SHA})
        expected = b"exact-index"
        responses = [
            (302, b"", f"/index.html?{query}"),
            (200, expected, None),
        ]
        deadlines: list[float] = []

        def public_response(_url, deadline):
            deadlines.append(deadline)
            return responses.pop(0)

        with mock.patch.object(
            MODULE, "_public_response", side_effect=public_response
        ):
            actual = MODULE._fetch_public_index(origin, SOURCE_SHA, 1234.5)
        self.assertEqual(actual, expected)
        self.assertEqual(deadlines, [1234.5, 1234.5])
        self.assertEqual(
            MODULE.require_exact_public_index(actual, expected), MODULE.sha256_bytes(expected)
        )

    def test_static_redirect_rejects_cross_origin_and_unexpected_status(self) -> None:
        origin = "https://szlholdings-example.static.hf.space"
        query = urllib.parse.urlencode({"source": SOURCE_SHA})
        with mock.patch.object(
            MODULE,
            "_public_response",
            return_value=(302, b"", f"https://evil.example/index.html?{query}"),
        ):
            with self.assertRaisesRegex(MODULE.ContractError, "unsafe redirect"):
                MODULE._fetch_public_index(origin, SOURCE_SHA, float("inf"))
        with mock.patch.object(
            MODULE, "_public_response", return_value=(200, b"unexpected", None)
        ):
            with self.assertRaisesRegex(MODULE.ContractError, "expected one 302"):
                MODULE._fetch_public_index(origin, SOURCE_SHA, float("inf"))

    def test_public_index_rejects_wrong_bytes(self) -> None:
        with self.assertRaisesRegex(MODULE.ContractError, "public index bytes differ"):
            MODULE.require_exact_public_index(b"wrong", b"expected")

    def test_transient_readback_retries_and_sanitizes_diagnostics(self) -> None:
        calls = []

        def action():
            calls.append("attempt")
            if len(calls) < 3:
                raise MODULE.TransientReadbackError("token=raw-secret")
            return "closed"

        with mock.patch.object(MODULE.time, "monotonic", return_value=0.0):
            with mock.patch.object(MODULE.time, "sleep"):
                self.assertEqual(MODULE._retry_transient(action, 1.0, "test"), "closed")
        self.assertEqual(len(calls), 3)
        diagnostic = MODULE._sanitized_diagnostic(
            MODULE.TransientReadbackError("token=raw-secret")
        )
        self.assertNotIn("raw-secret", diagnostic)
        self.assertIn("<redacted>", diagnostic)

    def test_request_timeout_is_capped_by_remaining_deadline(self) -> None:
        with mock.patch.object(MODULE.time, "monotonic", return_value=100.0):
            self.assertEqual(
                MODULE._remaining_timeout(105.0, 30.0, "request"), 5.0
            )
            self.assertEqual(
                MODULE._remaining_timeout(200.0, 30.0, "request"), 30.0
            )
            with self.assertRaisesRegex(MODULE.ContractError, "deadline expired"):
                MODULE._remaining_timeout(100.0, 30.0, "request")

    def test_terminal_public_bytes_fail_without_retry(self) -> None:
        with mock.patch.object(
            MODULE, "_fetch_public_index", return_value=b"wrong"
        ) as fetch:
            with mock.patch.object(MODULE, "_public_response") as provenance:
                with self.assertRaisesRegex(MODULE.ContractError, "bytes differ"):
                    MODULE._read_exact_public_identity(
                        "https://szlholdings-example.static.hf.space",
                        SOURCE_SHA,
                        b"expected",
                        b"provenance",
                        MODULE.time.monotonic() + 10,
                    )
        fetch.assert_called_once()
        provenance.assert_not_called()

    def test_attestation_reauthorizes_after_exact_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            output_path = root / "success.json"
            partial_path = root / "partial.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            event_path = root / "event.json"
            authorization_output_path = root / "post-readback-authorization.json"
            write_push_event(event_path)
            write_deploy_result(bundle, result_path)
            events: list[str] = []

            deadlines: list[float] = []

            def hf_json(url: str, deadline: float):
                deadlines.append(deadline)
                if "/tree/" in url:
                    events.append("tree")
                    return live_tree(bundle)
                events.append("runtime")
                return {"sha": TARGET_SHA, "runtime": {"stage": "RUNNING"}}

            def public_index(_origin, _source_sha, deadline):
                deadlines.append(deadline)
                events.append("index")
                return (bundle / "index.html").read_bytes()

            def provenance(_url, deadline):
                deadlines.append(deadline)
                events.append("provenance")
                return 200, (bundle / "SPACE_PROVENANCE.json").read_bytes(), None

            def authorize(*_args):
                events.append("guard")
                return governed_merge_evidence()

            with mock.patch.object(MODULE, "_hf_json", side_effect=hf_json):
                with mock.patch.object(
                    MODULE, "_fetch_public_index", side_effect=public_index
                ):
                    with mock.patch.object(
                        MODULE, "_public_response", side_effect=provenance
                    ):
                        with mock.patch.object(
                            MODULE, "require_governed_main", side_effect=authorize
                        ):
                            attestation = MODULE.attest_bundle(
                                bundle,
                                SOURCE_SHA,
                                result_path,
                                output_path,
                                10,
                                MODULE.DEFAULT_CONFIG,
                                partial_path,
                                authorization_path=authorization_path,
                                event_path=event_path,
                                authorization_output_path=authorization_output_path,
                            )
            self.assertEqual(attestation["status"], "MEASURED")
            self.assertEqual(
                attestation["source"],
                {
                    "repository": MODULE.load_config()["source_repository"],
                    "revision": SOURCE_SHA,
                    "relation": MODULE.SOURCE_RELATION,
                },
            )
            self.assertEqual(events, ["runtime", "tree", "index", "provenance", "guard"])
            self.assertEqual(len(deadlines), 4)
            self.assertEqual(len(set(deadlines)), 1)
            self.assertTrue(output_path.is_file())
            self.assertFalse(partial_path.exists())

    def test_post_readback_drift_writes_partial_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            output_path = root / "success.json"
            partial_path = root / "partial.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            event_path = root / "event.json"
            authorization_output_path = root / "post-readback-authorization.json"
            write_push_event(event_path)
            write_deploy_result(bundle, result_path)

            def hf_json(url: str, _deadline: float):
                if "/tree/" in url:
                    return live_tree(bundle)
                return {"sha": TARGET_SHA, "runtime": {"stage": "RUNNING"}}

            with mock.patch.object(MODULE, "_hf_json", side_effect=hf_json):
                with mock.patch.object(
                    MODULE,
                    "_fetch_public_index",
                    return_value=(bundle / "index.html").read_bytes(),
                ):
                    with mock.patch.object(
                        MODULE,
                        "_public_response",
                        return_value=(
                            200,
                            (bundle / "SPACE_PROVENANCE.json").read_bytes(),
                            None,
                        ),
                    ):
                        with mock.patch.object(
                            MODULE,
                            "require_governed_main",
                            side_effect=MODULE.ContractError("main drifted"),
                        ):
                            with self.assertRaisesRegex(
                                MODULE.ContractError, "partial evidence"
                            ):
                                MODULE.attest_bundle(
                                    bundle,
                                    SOURCE_SHA,
                                    result_path,
                                    output_path,
                                    10,
                                    MODULE.DEFAULT_CONFIG,
                                    partial_path,
                                    authorization_path=authorization_path,
                                    event_path=event_path,
                                    authorization_output_path=authorization_output_path,
                                )
            partial = json.loads(partial_path.read_text(encoding="utf-8"))
            self.assertEqual(partial["status"], "PARTIAL_AFTER_MUTATION")
            self.assertFalse(partial["measured"])
            self.assertFalse(partial["live_success"])
            self.assertEqual(partial["hf_revision"], TARGET_SHA)
            self.assertEqual(partial["failure_stage"], "post_readback_governance")
            self.assertFalse(output_path.exists())

    def test_exhausted_runtime_readback_writes_exact_partial_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            output_path = root / "success.json"
            partial_path = root / "partial.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            event_path = root / "event.json"
            authorization_output_path = root / "post-readback-authorization.json"
            write_push_event(event_path)
            write_deploy_result(bundle, result_path)
            with mock.patch.object(
                MODULE,
                "_wait_for_exact_running",
                side_effect=MODULE.ContractError(
                    "runtime transient deadline exhausted token=raw-secret"
                ),
            ):
                with self.assertRaisesRegex(MODULE.ContractError, "partial evidence"):
                    MODULE.attest_bundle(
                        bundle,
                        SOURCE_SHA,
                        result_path,
                        output_path,
                        1,
                        MODULE.DEFAULT_CONFIG,
                        partial_path,
                        authorization_path=authorization_path,
                        event_path=event_path,
                        authorization_output_path=authorization_output_path,
                    )
            partial = json.loads(partial_path.read_text(encoding="utf-8"))
            self.assertEqual(partial["hf_revision"], TARGET_SHA)
            self.assertEqual(partial["failure_stage"], "runtime_readback")
            self.assertNotIn("raw-secret", partial["diagnostic"])
            self.assertFalse(output_path.exists())

    def test_workflow_stage_failures_preserve_exact_revision_without_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            measurement_path = root / "measurement.json"
            mutation_failure_path = root / "mutation-failure.json"
            partial_path = root / "partial.json"
            receipt_path = root / "receipt.json"
            workflow_failure_path = root / "workflow-failure.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            write_deploy_result(bundle, result_path)
            result = json.loads(result_path.read_text(encoding="utf-8"))
            measurement = {
                "schema": "szl.hf-live-attestation/v2",
                "status": "MEASURED",
                "source": {
                    "repository": MODULE.load_config()["source_repository"],
                    "revision": SOURCE_SHA,
                    "relation": MODULE.SOURCE_RELATION,
                },
                "source_revision": SOURCE_SHA,
                "hf_revision": TARGET_SHA,
                "target": result["target"],
                "receipt_minted": False,
                "deployment_success": False,
            }
            measurement_path.write_bytes(MODULE.canonical_json(measurement))
            cases = (
                ("failure", "skipped", "", "measurement_evidence_upload"),
                ("success", "failure", "", "oidc_attestation"),
                ("success", "success", "terminal_evidence_upload", "terminal_evidence_upload"),
            )
            for success_evidence, oidc, forced, expected_stage in cases:
                with self.subTest(stage=expected_stage):
                    failure = MODULE.synthesize_workflow_outcome(
                        SOURCE_SHA,
                        result_path,
                        measurement_path,
                        mutation_failure_path,
                        partial_path,
                        receipt_path,
                        workflow_failure_path,
                        "success",
                        "success",
                        success_evidence,
                        oidc,
                        "attestation-id" if oidc == "success" else "",
                        "https://github.example/attestation" if oidc == "success" else "",
                        forced,
                    )
                    self.assertEqual(failure["status"], "WORKFLOW_STAGE_FAILURE")
                    self.assertEqual(failure["failure_stage"], expected_stage)
                    self.assertEqual(failure["source"], measurement["source"])
                    self.assertEqual(failure["hf_revision"], TARGET_SHA)
                    self.assertFalse(failure["receipt_minted"])
                    self.assertFalse(failure["deployment_success"])
                    self.assertFalse(receipt_path.exists())
                    self.assertEqual(
                        workflow_failure_path.read_bytes(),
                        MODULE.canonical_json(failure),
                    )

    def test_upstream_stage_outcomes_are_classified_before_mutation(self) -> None:
        cases = (
            ({"authorization_outcome": "failure"}, "governance_authorization"),
            ({"publisher_input_outcome": "failure"}, "publisher_input"),
            ({"publisher_environment_outcome": "failure"}, "publisher_environment"),
            ({"publisher_evidence_outcome": "failure"}, "publisher_evidence_upload"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for options, expected_stage in cases:
                with self.subTest(stage=expected_stage):
                    failure = MODULE.synthesize_workflow_outcome(
                        SOURCE_SHA,
                        root / "missing-result.json",
                        root / "missing-measurement.json",
                        root / "missing-mutation.json",
                        root / "missing-partial.json",
                        root / "receipt.json",
                        root / "workflow-failure.json",
                        "success",
                        "success",
                        "success",
                        "success",
                        **options,
                    )
                    self.assertEqual(failure["failure_stage"], expected_stage)
                    self.assertFalse(failure["deployment_success"])
                    self.assertFalse((root / "receipt.json").exists())

    def test_successful_oidc_outcome_mints_exact_measurement_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            measurement_path = root / "measurement.json"
            mutation_failure_path = root / "mutation-failure.json"
            partial_path = root / "partial.json"
            receipt_path = root / "receipt.json"
            workflow_failure_path = root / "workflow-failure.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            write_deploy_result(bundle, result_path)
            result = json.loads(result_path.read_text(encoding="utf-8"))
            measurement = {
                "schema": "szl.hf-live-attestation/v2",
                "status": "MEASURED",
                "source": {
                    "repository": MODULE.load_config()["source_repository"],
                    "revision": SOURCE_SHA,
                    "relation": MODULE.SOURCE_RELATION,
                },
                "source_revision": SOURCE_SHA,
                "hf_revision": TARGET_SHA,
                "target": result["target"],
                "receipt_minted": False,
                "deployment_success": False,
            }
            measurement_path.write_bytes(MODULE.canonical_json(measurement))
            receipt = MODULE.synthesize_workflow_outcome(
                SOURCE_SHA,
                result_path,
                measurement_path,
                mutation_failure_path,
                partial_path,
                receipt_path,
                workflow_failure_path,
                "success",
                "success",
                "success",
                "success",
                "attestation-id",
                "https://github.example/attestation",
            )
            self.assertEqual(receipt["status"], "OIDC_ATTESTED_DEPLOYMENT")
            self.assertEqual(receipt["source"], measurement["source"])
            self.assertEqual(receipt["source_revision"], SOURCE_SHA)
            self.assertEqual(receipt["hf_revision"], TARGET_SHA)
            self.assertEqual(
                receipt["measurement"]["sha256"],
                MODULE.sha256_bytes(measurement_path.read_bytes()),
            )
            self.assertTrue(receipt["receipt_minted"])
            self.assertTrue(receipt["deployment_success"])
            self.assertEqual(receipt_path.read_bytes(), MODULE.canonical_json(receipt))
            self.assertFalse(workflow_failure_path.exists())

    def test_workflow_outcome_rejects_invalid_or_cross_repo_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            measurement_path = root / "measurement.json"
            mutation_failure_path = root / "mutation-failure.json"
            partial_path = root / "partial.json"
            receipt_path = root / "receipt.json"
            workflow_failure_path = root / "workflow-failure.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            write_deploy_result(bundle, result_path)
            config = MODULE.load_config()
            expected_source = {
                "repository": config["source_repository"],
                "revision": SOURCE_SHA,
                "relation": MODULE.SOURCE_RELATION,
            }
            base_measurement = {
                "schema": "szl.hf-live-attestation/v2",
                "status": "MEASURED",
                "source": expected_source,
                "source_revision": SOURCE_SHA,
                "hf_revision": TARGET_SHA,
                "target": config["target"],
                "receipt_minted": False,
                "deployment_success": False,
            }
            invalid_measurements = {}
            for field in ("repository", "relation"):
                missing = copy.deepcopy(base_measurement)
                del missing["source"][field]
                invalid_measurements[f"missing_{field}"] = missing
                wrong = copy.deepcopy(base_measurement)
                wrong["source"][field] = f"wrong-{field}"
                invalid_measurements[f"wrong_{field}"] = wrong
            missing_target = copy.deepcopy(base_measurement)
            del missing_target["target"]
            invalid_measurements["missing_target"] = missing_target
            wrong_target = copy.deepcopy(base_measurement)
            wrong_target["target"] = "SZLHOLDINGS/wrong-target"
            invalid_measurements["wrong_target"] = wrong_target

            for case, measurement in invalid_measurements.items():
                with self.subTest(case=case):
                    measurement_path.write_bytes(MODULE.canonical_json(measurement))
                    failure = MODULE.synthesize_workflow_outcome(
                        SOURCE_SHA,
                        result_path,
                        measurement_path,
                        mutation_failure_path,
                        partial_path,
                        receipt_path,
                        workflow_failure_path,
                        "success",
                        "success",
                        "success",
                        "success",
                        "attestation-id",
                        "https://github.example/attestation",
                    )
                    self.assertEqual(failure["failure_stage"], "local_measurement_schema")
                    self.assertEqual(failure["source"], measurement.get("source"))
                    self.assertEqual(failure["expected_source"], expected_source)
                    self.assertFalse(failure["receipt_minted"])
                    self.assertFalse(failure["deployment_success"])
                    self.assertFalse(receipt_path.exists())

            cross_repository = next(
                repository
                for repository in MODULE.TARGET_REPOSITORY_IDS
                if repository != config["source_repository"]
            )
            cross_config = dict(config)
            cross_config["source_repository"] = cross_repository
            cross_config["target"] = "SZLHOLDINGS/" + cross_repository.split("/", 1)[1]
            cross_config_path = root / "cross-repo-config.json"
            cross_config_path.write_bytes(MODULE.canonical_json(cross_config))
            measurement_path.write_bytes(MODULE.canonical_json(base_measurement))
            failure = MODULE.synthesize_workflow_outcome(
                SOURCE_SHA,
                result_path,
                measurement_path,
                mutation_failure_path,
                partial_path,
                receipt_path,
                workflow_failure_path,
                "success",
                "success",
                "success",
                "success",
                "attestation-id",
                "https://github.example/attestation",
                config_path=cross_config_path,
            )
            self.assertEqual(failure["failure_stage"], "local_measurement_schema")
            self.assertEqual(failure["source"], expected_source)
            self.assertEqual(failure["expected_source"]["repository"], cross_repository)
            self.assertEqual(failure["expected_target"], cross_config["target"])
            self.assertFalse(failure["receipt_minted"])
            self.assertFalse(failure["deployment_success"])
            self.assertFalse(receipt_path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
