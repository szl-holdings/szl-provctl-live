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
RELEASE_CHECK_SUITE_ID = 198
BOUNDARY_CHECK_SUITE_ID = 199


def exact_pr_body(repository: str, head_sha: str = PR_HEAD_SHA) -> str:
    payload = {
        "head_revision": head_sha,
        "repository": repository,
        "schema": MODULE.PR_BODY_MARKER_SCHEMA,
    }
    marker = (
        MODULE.PR_BODY_MARKER_PREFIX
        + json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + MODULE.PR_BODY_MARKER_SUFFIX
    )
    return f"Release evidence for the exact reviewed head.\n\n{marker}\n"


def exact_job_evidence(
    name: str,
    job_id: int,
    run_id: int,
    run_attempt: int,
    check_suite_id: int,
    conclusion: str = "success",
) -> dict:
    return {
        "app_id": MODULE.GITHUB_ACTIONS_INTEGRATION_ID,
        "check_run_id": job_id,
        "check_suite_id": check_suite_id,
        "conclusion": conclusion,
        "head_revision": PR_HEAD_SHA,
        "job_id": job_id,
        "name": name,
        "run_attempt": run_attempt,
        "run_id": run_id,
        "status": "completed",
    }


def exact_workflow_evidence(
    repository: str,
    *,
    run_id: int,
    run_attempt: int,
    check_suite_id: int,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
    jobs: list[dict],
) -> dict:
    return {
        "base_revision": PARENT_SHA,
        "check_suite_id": check_suite_id,
        "conclusion": "success",
        "event": "pull_request",
        "head_ref": "release-candidate",
        "head_revision": PR_HEAD_SHA,
        "jobs": sorted(jobs, key=lambda row: (row["name"], row["job_id"])),
        "name": workflow_name,
        "path": workflow_path,
        "pull_request_number": 7,
        "repository_id": MODULE.TARGET_REPOSITORY_IDS[repository],
        "run_attempt": run_attempt,
        "run_id": run_id,
        "status": "completed",
        "workflow_id": workflow_id,
    }


def governed_merge_evidence(source_sha: str = SOURCE_SHA) -> dict:
    repository = MODULE.load_config()["source_repository"]
    body = exact_pr_body(repository)
    release_jobs = [
        exact_job_evidence(
            name,
            index + 10,
            RELEASE_RUN_ID,
            1,
            RELEASE_CHECK_SUITE_ID,
        )
        for index, name in enumerate(sorted(MODULE.REQUIRED_STATUS_CONTEXTS))
    ]
    boundary_jobs = [
        exact_job_evidence(
            "release-boundary-required",
            20,
            BOUNDARY_RUN_ID,
            1,
            BOUNDARY_CHECK_SUITE_ID,
        )
    ]
    return {
        "schema": MODULE.GOVERNED_MERGE_SCHEMA,
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
            "body_evidence": {
                "body_sha256": MODULE.sha256_bytes(body.encode("utf-8")),
                "head_revision": PR_HEAD_SHA,
                "repository": repository,
                "schema": MODULE.PR_BODY_EVIDENCE_SCHEMA,
            },
            "head_ref": "release-candidate",
            "head_revision": PR_HEAD_SHA,
            "id": 70,
            "merge_revision": source_sha,
            "merged_at": "2026-08-10T00:00:00Z",
            "merged_by": "solo-owner",
            "number": 7,
        },
        "required_checks": sorted(release_jobs, key=lambda row: row["name"]),
        "release_workflow": exact_workflow_evidence(
            repository,
            run_id=RELEASE_RUN_ID,
            run_attempt=1,
            check_suite_id=RELEASE_CHECK_SUITE_ID,
            workflow_id=MODULE.TARGET_RELEASE_WORKFLOW_IDS[repository],
            workflow_name=MODULE.RELEASE_WORKFLOW_NAME,
            workflow_path=MODULE.RELEASE_WORKFLOW_PATH,
            jobs=release_jobs,
        ),
        "required_workflow": exact_workflow_evidence(
            repository,
            run_id=BOUNDARY_RUN_ID,
            run_attempt=1,
            check_suite_id=BOUNDARY_CHECK_SUITE_ID,
            workflow_id=MODULE.TARGET_REQUIRED_WORKFLOW_IDS[repository],
            workflow_name=MODULE.REQUIRED_WORKFLOW_NAME,
            workflow_path=MODULE.REQUIRED_WORKFLOW_PATH,
            jobs=boundary_jobs,
        ),
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
    associated_pages: list[list[dict]] | None = None,
    associated_second_pages: list[list[dict]] | None = None,
    initial_body: str | None = None,
    final_body: str | None = None,
    release_attempt: int = 1,
    current_release_attempt: int | None = None,
    wrong_job_run: bool = False,
    wrong_check_suite: bool = False,
    wrong_check_url: bool = False,
    final_main_sha: str = SOURCE_SHA,
):
    repository = MODULE.load_config()["source_repository"]
    repository_id = MODULE.TARGET_REPOSITORY_IDS[repository]
    body = initial_body if initial_body is not None else exact_pr_body(repository)
    final_body = body if final_body is None else final_body
    branch_calls = 0
    pull_calls = 0
    associated_scan = -1

    def full_pull(pull_body: str) -> dict:
        return {
            "id": 70,
            "number": 7,
            "state": "closed",
            "merged": True,
            "merged_at": "2026-08-10T00:00:00Z",
            "merge_commit_sha": SOURCE_SHA,
            "merged_by": {"login": "solo-owner"},
            "body": pull_body,
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
        attempt: int,
        check_suite_id: int,
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
            "status": "completed" if conclusion != "in_progress" else "in_progress",
            "conclusion": None if conclusion == "in_progress" else conclusion,
            "run_attempt": attempt,
            "check_suite_id": check_suite_id,
            "repository": {"full_name": repository, "id": repository_id},
            "pull_requests": [run_pull(pull_number)],
        }

    def release_run(attempt: int = release_attempt) -> dict:
        return workflow_run(
            RELEASE_RUN_ID,
            MODULE.TARGET_RELEASE_WORKFLOW_IDS[repository],
            MODULE.RELEASE_WORKFLOW_NAME,
            MODULE.RELEASE_WORKFLOW_PATH,
            release_conclusion,
            attempt,
            RELEASE_CHECK_SUITE_ID,
        )

    def boundary_run(
        run_id: int = BOUNDARY_RUN_ID,
        conclusion: str = boundary_conclusion,
    ) -> dict:
        return workflow_run(
            run_id,
            MODULE.TARGET_REQUIRED_WORKFLOW_IDS[repository],
            MODULE.REQUIRED_WORKFLOW_NAME,
            MODULE.REQUIRED_WORKFLOW_PATH,
            conclusion,
            1,
            BOUNDARY_CHECK_SUITE_ID if run_id == BOUNDARY_RUN_ID else BOUNDARY_CHECK_SUITE_ID + 100,
            pull_number=8 if misbound_boundary else 7,
        )

    def workflow_rows() -> list[dict]:
        rows = [release_run()]
        if stale_boundary_success:
            rows.append(boundary_run(BOUNDARY_RUN_ID, "success"))
            rows.append(boundary_run(BOUNDARY_RUN_ID + 100, boundary_conclusion))
        else:
            rows.append(boundary_run())
        return rows

    def job(
        job_id: int,
        run_id: int,
        workflow_name: str,
        name: str,
    ) -> dict:
        actual_run_id = run_id + 500 if wrong_job_run and run_id == RELEASE_RUN_ID else run_id
        check_id = job_id + 500 if wrong_check_url and run_id == RELEASE_RUN_ID else job_id
        return {
            "id": job_id,
            "run_id": actual_run_id,
            "run_url": f"https://api.github.test/repos/{repository}/actions/runs/{run_id}",
            "head_sha": PR_HEAD_SHA,
            "workflow_name": workflow_name,
            "name": name,
            "status": "completed",
            "conclusion": "success",
            "html_url": f"https://github.com/{repository}/actions/runs/{run_id}/job/{job_id}",
            "check_run_url": f"https://api.github.test/repos/{repository}/check-runs/{check_id}",
        }

    release_jobs = [
        job(index + 10, RELEASE_RUN_ID, MODULE.RELEASE_WORKFLOW_NAME, name)
        for index, name in enumerate(sorted(MODULE.REQUIRED_STATUS_CONTEXTS))
    ]
    boundary_jobs = [
        job(20, BOUNDARY_RUN_ID, MODULE.REQUIRED_WORKFLOW_NAME, "release-boundary-required")
    ]

    def checks_for(jobs: list[dict], suite_id: int) -> list[dict]:
        rows = []
        for item in jobs:
            check_id = (
                item["id"]
                if wrong_check_url and suite_id == RELEASE_CHECK_SUITE_ID
                else int(item["check_run_url"].rsplit("/", 1)[1])
            )
            conclusion = (
                "failure"
                if stale_check_success and suite_id == RELEASE_CHECK_SUITE_ID
                else item["conclusion"]
            )
            rows.append(
                {
                    "id": check_id,
                    "name": item["name"],
                    "head_sha": PR_HEAD_SHA,
                    "status": "completed",
                    "conclusion": conclusion,
                    "url": item["check_run_url"],
                    "details_url": item["html_url"],
                    "check_suite": {
                        "id": suite_id + 500
                        if wrong_check_suite and suite_id == RELEASE_CHECK_SUITE_ID
                        else suite_id
                    },
                    "app": {"id": check_app_id},
                }
            )
        return rows

    initial_pull = full_pull(body)
    if associated_pages is None:
        associated_pages = [[copy.deepcopy(initial_pull)]]
    if associated_second_pages is None:
        associated_second_pages = copy.deepcopy(associated_pages)

    def respond(url: str, token: str = "") -> object:
        nonlocal associated_scan, branch_calls, pull_calls
        if token != "github-test-token":
            raise AssertionError("guard omitted its GitHub credential")
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        if path == f"/repos/{repository}":
            return {
                "id": repository_id,
                "full_name": repository,
                "default_branch": "main",
            }
        if path == f"/repos/{repository}/branches/main":
            branch_calls += 1
            return {"commit": {"sha": SOURCE_SHA if branch_calls == 1 else final_main_sha}}
        if path == f"/repos/{repository}/commits/{SOURCE_SHA}/pulls":
            page = int(query.get("page", ["1"])[0])
            if page == 1:
                associated_scan += 1
            pages = associated_pages if associated_scan == 0 else associated_second_pages
            return copy.deepcopy(pages[page - 1] if page <= len(pages) else [])
        if path == f"/repos/{repository}/pulls/7":
            pull_calls += 1
            return full_pull(body if pull_calls == 1 else final_body)
        if path == f"/repos/{repository}/actions/runs":
            if query.get("head_sha") != [PR_HEAD_SHA] or query.get("event") != [
                "pull_request"
            ]:
                raise AssertionError("workflow query is not exact")
            rows = workflow_rows()
            return {"total_count": len(rows), "workflow_runs": rows}
        if path == f"/repos/{repository}/actions/runs/{RELEASE_RUN_ID}/attempts/{release_attempt}":
            return release_run()
        if path == f"/repos/{repository}/actions/runs/{BOUNDARY_RUN_ID}/attempts/1":
            return boundary_run()
        if stale_boundary_success and path == f"/repos/{repository}/actions/runs/{BOUNDARY_RUN_ID + 100}/attempts/1":
            return boundary_run(BOUNDARY_RUN_ID + 100, boundary_conclusion)
        if path == f"/repos/{repository}/actions/runs/{RELEASE_RUN_ID}/attempts/{release_attempt}/jobs":
            return {"total_count": len(release_jobs), "jobs": copy.deepcopy(release_jobs)}
        if path == f"/repos/{repository}/actions/runs/{BOUNDARY_RUN_ID}/attempts/1/jobs":
            return {"total_count": len(boundary_jobs), "jobs": copy.deepcopy(boundary_jobs)}
        if stale_boundary_success and path == f"/repos/{repository}/actions/runs/{BOUNDARY_RUN_ID + 100}/attempts/1/jobs":
            stale_jobs = [
                job(
                    120,
                    BOUNDARY_RUN_ID + 100,
                    MODULE.REQUIRED_WORKFLOW_NAME,
                    "release-boundary-required",
                )
            ]
            return {"total_count": 1, "jobs": stale_jobs}
        if path == f"/repos/{repository}/check-suites/{RELEASE_CHECK_SUITE_ID}/check-runs":
            rows = checks_for(release_jobs, RELEASE_CHECK_SUITE_ID)
            return {"total_count": len(rows), "check_runs": rows}
        if path == f"/repos/{repository}/check-suites/{BOUNDARY_CHECK_SUITE_ID}/check-runs":
            rows = checks_for(boundary_jobs, BOUNDARY_CHECK_SUITE_ID)
            return {"total_count": len(rows), "check_runs": rows}
        if path == f"/repos/{repository}/actions/runs/{RELEASE_RUN_ID}":
            return release_run(
                release_attempt
                if current_release_attempt is None
                else current_release_attempt
            )
        if path == f"/repos/{repository}/actions/runs/{BOUNDARY_RUN_ID}":
            return boundary_run()
        if stale_boundary_success and path == f"/repos/{repository}/actions/runs/{BOUNDARY_RUN_ID + 100}":
            return boundary_run(BOUNDARY_RUN_ID + 100, boundary_conclusion)
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
            self.assertEqual(result["schema"], MODULE.GOVERNED_MERGE_SCHEMA)
            self.assertEqual(result["push"], {"before": PARENT_SHA, "after": SOURCE_SHA})
            self.assertEqual(result["pull_request"]["head_revision"], PR_HEAD_SHA)
            self.assertEqual(
                result["pull_request"]["body_evidence"]["schema"],
                MODULE.PR_BODY_EVIDENCE_SCHEMA,
            )
            self.assertEqual(result["release_workflow"]["run_attempt"], 1)
            self.assertEqual(
                {row["name"] for row in result["release_workflow"]["jobs"]},
                set(MODULE.REQUIRED_STATUS_CONTEXTS),
            )
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
                    "job/check binding",
                ),
                (
                    "misbound boundary",
                    guard_responder(misbound_boundary=True),
                    "exact required release-boundary workflow did not run",
                ),
                (
                    "failed publisher workflow",
                    guard_responder(release_conclusion="failure"),
                    "latest exact publisher workflow",
                ),
                (
                    "wrong check app",
                    guard_responder(check_app_id=99),
                    "job/check binding",
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

    def test_guard_paginates_complete_stable_associated_pr_inventory(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        candidate = {
            "id": 70,
            "number": 7,
            "state": "closed",
            "merged_at": "2026-08-10T00:00:00Z",
            "merge_commit_sha": SOURCE_SHA,
            "base": {
                "ref": "main",
                "sha": PARENT_SHA,
                "repo": {"full_name": repository},
            },
        }
        noise = [{"id": 1000 + index, "state": "open"} for index in range(100)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    MODULE,
                    "_request_json",
                    side_effect=guard_responder(
                        associated_pages=[noise, [candidate]],
                    ),
                ):
                    result = MODULE.require_governed_main(
                        SOURCE_SHA, event_path, root / "authorization.json"
                    )
            self.assertEqual(result["pull_request"]["id"], 70)

    def test_guard_rejects_incomplete_ambiguous_or_drifting_pr_inventory(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        candidate = {
            "id": 70,
            "number": 7,
            "state": "closed",
            "merged_at": "2026-08-10T00:00:00Z",
            "merge_commit_sha": SOURCE_SHA,
            "base": {
                "ref": "main",
                "sha": PARENT_SHA,
                "repo": {"full_name": repository},
            },
        }
        second = copy.deepcopy(candidate)
        second.update({"id": 71, "number": 8})
        noise = [{"id": 1000 + index, "state": "open"} for index in range(99)]
        duplicate_page = [{"id": 1000, "state": "open"}]
        variants = [
            (
                "ambiguous later page",
                guard_responder(
                    associated_pages=[[candidate, *noise], [second]]
                ),
                "unambiguous merged PR",
            ),
            (
                "duplicate across pages",
                guard_responder(
                    associated_pages=[[candidate, *noise], duplicate_page]
                ),
                "malformed or duplicated",
            ),
            (
                "snapshot drift",
                guard_responder(
                    associated_pages=[[candidate]],
                    associated_second_pages=[
                        [candidate, {"id": 72, "state": "open"}]
                    ],
                ),
                "inventory changed",
            ),
            (
                "main drift",
                guard_responder(final_main_sha=TARGET_SHA),
                "protected main changed",
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                for label, responder, diagnostic in variants:
                    with self.subTest(label=label):
                        with mock.patch.object(
                            MODULE, "_request_json", side_effect=responder
                        ):
                            with self.assertRaisesRegex(
                                MODULE.ContractError, diagnostic
                            ):
                                MODULE.require_governed_main(
                                    SOURCE_SHA,
                                    event_path,
                                    root / f"{label}.json",
                                )

    def test_guard_rejects_attempt_job_and_check_misbinding(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        variants = [
            ("job from another run", guard_responder(wrong_job_run=True), "job/check binding"),
            ("check from another suite", guard_responder(wrong_check_suite=True), "job/check binding"),
            ("job/check URL mismatch", guard_responder(wrong_check_url=True), "job/check binding"),
            (
                "new run attempt",
                guard_responder(current_release_attempt=2),
                "advanced after exact-attempt",
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                for label, responder, diagnostic in variants:
                    with self.subTest(label=label):
                        with mock.patch.object(
                            MODULE, "_request_json", side_effect=responder
                        ):
                            with self.assertRaisesRegex(
                                MODULE.ContractError, diagnostic
                            ):
                                MODULE.require_governed_main(
                                    SOURCE_SHA,
                                    event_path,
                                    root / f"{label}.json",
                                )

    def test_exact_pr_body_marker_and_event_binding(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        repository_id = MODULE.TARGET_REPOSITORY_IDS[repository]
        body = exact_pr_body(repository)
        evidence = MODULE.exact_pr_body_evidence(body, repository, PR_HEAD_SHA)
        self.assertEqual(evidence["schema"], MODULE.PR_BODY_EVIDENCE_SCHEMA)
        marker = body.strip().splitlines()[-1]
        invalid = [
            None,
            body + marker + "\n",
            body.replace(PR_HEAD_SHA, TARGET_SHA),
            body.replace(repository, "szl-holdings/other"),
            body.replace('"schema":"szl.pr-head/v1"', '"schema":"wrong"'),
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(MODULE.ContractError):
                    MODULE.exact_pr_body_evidence(value, repository, PR_HEAD_SHA)
        with tempfile.TemporaryDirectory() as temporary:
            event_path = Path(temporary) / "pull-event.json"
            event_path.write_text(
                json.dumps(
                    {
                        "repository": {"id": repository_id, "full_name": repository},
                        "pull_request": {
                            "body": body,
                            "head": {
                                "sha": PR_HEAD_SHA,
                                "repo": {
                                    "id": repository_id,
                                    "full_name": repository,
                                },
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                MODULE.validate_pr_body_event(PR_HEAD_SHA, event_path), evidence
            )

    def test_guard_rejects_pr_body_drift_after_exact_checks(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        body = exact_pr_body(repository)
        changed = body.replace("Release evidence", "Changed release evidence")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            event_path = root / "event.json"
            write_push_event(event_path)
            with mock.patch.dict(os.environ, environment, clear=False):
                with mock.patch.object(
                    MODULE,
                    "_request_json",
                    side_effect=guard_responder(
                        initial_body=body, final_body=changed
                    ),
                ):
                    with self.assertRaisesRegex(
                        MODULE.ContractError, "evidence changed"
                    ):
                        MODULE.require_governed_main(
                            SOURCE_SHA, event_path, root / "authorization.json"
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

    def test_governed_merge_v3_rejects_body_and_job_binding_tamper(self) -> None:
        variants = []
        wrong_body = governed_merge_evidence()
        wrong_body["pull_request"]["body_evidence"]["head_revision"] = TARGET_SHA
        variants.append(wrong_body)
        wrong_attempt = governed_merge_evidence()
        wrong_attempt["release_workflow"]["jobs"][0]["run_attempt"] = 2
        variants.append(wrong_attempt)
        wrong_suite = governed_merge_evidence()
        wrong_suite["required_workflow"]["jobs"][0]["check_suite_id"] += 1
        variants.append(wrong_suite)
        wrong_required = governed_merge_evidence()
        wrong_required["required_checks"] = wrong_required["required_checks"][:-1]
        variants.append(wrong_required)
        with tempfile.TemporaryDirectory() as temporary:
            authorization = Path(temporary) / "governed-merge.json"
            for index, evidence in enumerate(variants):
                with self.subTest(index=index):
                    authorization.write_bytes(MODULE.canonical_json(evidence))
                    with self.assertRaises(MODULE.ContractError):
                        MODULE.load_governed_merge(authorization, SOURCE_SHA)

    def test_guard_api_error_fails_closed(self) -> None:
        with mock.patch.object(
            MODULE.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ):
            with self.assertRaisesRegex(MODULE.ContractError, "JSON request failed closed"):
                MODULE._request_json("https://api.github.test/repos/example/repo", "token")

    def test_public_main_freshness_is_anonymous_exact_and_canonical(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        ref_url = f"{MODULE.PUBLIC_GITHUB_API_ROOT}/repos/{repository}/git/ref/heads/main"
        commit_url = (
            f"{MODULE.PUBLIC_GITHUB_API_ROOT}/repos/{repository}/git/commits/{SOURCE_SHA}"
        )
        responses = [
            {"sha": SOURCE_SHA, "url": commit_url},
            {
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": SOURCE_SHA, "url": commit_url},
            },
        ]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-main-freshness.json"
            with mock.patch.object(
                MODULE, "_request_json", side_effect=responses
            ) as request_json:
                evidence = MODULE.require_public_main_fresh(SOURCE_SHA, output)
            self.assertEqual(
                request_json.call_args_list,
                [mock.call(commit_url), mock.call(ref_url)],
            )
            self.assertEqual(evidence["schema"], "szl.github-public-main-freshness/v1")
            self.assertEqual(evidence["status"], "PUBLIC_MAIN_FRESH")
            self.assertEqual(evidence["credential_mode"], "anonymous_public_api")
            self.assertEqual(evidence["source_revision"], SOURCE_SHA)
            self.assertEqual(output.read_bytes(), MODULE.canonical_json(evidence))

    def test_public_main_freshness_rejects_stale_or_malformed_responses(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        commit_url = (
            f"{MODULE.PUBLIC_GITHUB_API_ROOT}/repos/{repository}/git/commits/{SOURCE_SHA}"
        )
        valid_commit = {"sha": SOURCE_SHA, "url": commit_url}
        variants = (
            [{"sha": TARGET_SHA, "url": commit_url}],
            [
                valid_commit,
                {"ref": "refs/heads/main", "object": {"type": "commit", "sha": TARGET_SHA, "url": commit_url}},
            ],
            [
                valid_commit,
                {"ref": "refs/heads/main", "object": {"type": "tag", "sha": SOURCE_SHA, "url": commit_url}},
            ],
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, responses in enumerate(variants):
                with self.subTest(index=index):
                    with mock.patch.object(MODULE, "_request_json", side_effect=responses):
                        with self.assertRaisesRegex(MODULE.ContractError, "public main"):
                            MODULE.require_public_main_fresh(
                                SOURCE_SHA, Path(temporary) / f"stale-{index}.json"
                            )

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
        self.assertIn(
            "types: [opened, synchronize, reopened, edited, ready_for_review]",
            workflow,
        )
        self.assertIn("hf_static_space.py pr-body", workflow)
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
        self.assertEqual(jobs["measure"]["timeout-minutes"], 20)
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
        authorize_steps = {
            step.get("id"): step for step in jobs["authorize"]["steps"] if step.get("id")
        }
        deploy_steps = {
            step.get("id"): step for step in jobs["deploy"]["steps"] if step.get("id")
        }
        measure_steps = {
            step.get("id"): step for step in jobs["measure"]["steps"] if step.get("id")
        }
        attest_steps = {
            step.get("id"): step for step in jobs["attest"]["steps"] if step.get("id")
        }
        self.assertEqual(
            jobs["authorize"]["outputs"]["authorization-evidence-outcome"],
            "${{ steps.authorization-evidence.outcome }}",
        )
        self.assertEqual(
            jobs["deploy"]["outputs"]["publisher-freshness-outcome"],
            "${{ steps.publisher-freshness.outcome }}",
        )
        self.assertIs(
            authorize_steps["publisher-input-evidence"]["with"]["include-hidden-files"],
            True,
        )
        self.assertIn("needs.authorize.result == 'success'", jobs["deploy"]["if"])
        self.assertIn(
            "needs.authorize.outputs.authorization-evidence-outcome == 'success'",
            jobs["deploy"]["if"],
        )
        self.assertIn(
            'mkdir -p "$RUNNER_TEMP/publication-evidence"',
            deploy_steps["publisher-environment"]["run"],
        )
        self.assertIn(
            'echo "PUBLISHER_VENV=$PUBLISHER_VENV" >> "$GITHUB_ENV"',
            deploy_steps["publisher-environment"]["run"],
        )
        self.assertIn(
            "steps.publisher-evidence-download.outcome == 'success'",
            attest_steps["oidc"]["if"],
        )
        self.assertIn(
            "steps.measurement-evidence-download.outcome == 'success'",
            attest_steps["oidc"]["if"],
        )
        self.assertEqual(jobs["measure"]["needs"], ["authorize", "deploy"])
        self.assertIn(
            "needs.measure.outputs.measurement-rebind-outcome == 'success'",
            attest_steps["oidc"]["if"],
        )
        self.assertIn(
            "needs.measure.outputs.measurement-environment-outcome == 'success'",
            attest_steps["oidc"]["if"],
        )
        self.assertNotIn("HF_TOKEN", authorize_text)
        self.assertIn("publisher_script_sha256", jobs["authorize"]["outputs"])
        self.assertIn("publisher_lock_sha256", jobs["authorize"]["outputs"])
        self.assertIn("publisher_config_sha256", jobs["authorize"]["outputs"])
        self.assertIn("authorization_sha256", jobs["authorize"]["outputs"])
        self.assertIn("bundle_manifest_sha256", jobs["authorize"]["outputs"])
        self.assertIn("requirements/hf-validator.lock", validate_text)
        self.assertNotIn("requirements/hf-publisher.lock", validate_text)
        self.assertNotIn("huggingface_hub", validate_text)
        self.assertNotIn("${{ github.token }}", deploy_text)
        self.assertNotIn("actions/checkout@", deploy_text)
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
        self.assertIn("--authorization-evidence-outcome", workflow)
        self.assertIn("--publisher-environment-outcome", workflow)
        self.assertIn("--publisher-freshness-outcome", workflow)
        self.assertIn("--publisher-rebind-outcome", workflow)
        self.assertIn("--publisher-evidence-outcome", workflow)
        self.assertIn("--publisher-evidence-download-outcome", workflow)
        self.assertIn("--measurement-evidence-download-outcome", workflow)
        self.assertIn("--measurement-hardening-outcome", workflow)
        self.assertIn("--measurement-input-outcome", workflow)
        self.assertIn("--measurement-rebind-outcome", workflow)
        self.assertIn("--measurement-publisher-evidence-outcome", workflow)
        self.assertIn("--measurement-environment-outcome", workflow)
        self.assertIn("--attestation-checkout-outcome", workflow)
        self.assertIn("--authorization", workflow)
        self.assertIn("--authorization-output", workflow)
        self.assertIn("Require terminal governed success", workflow)
        self.assertIn(
            "actions/attest-build-provenance@"
            "a2bbfa25375fe432b6a289bc6b6cd05ecd0c4c32",
            workflow,
        )
        deploy_steps = jobs["deploy"]["steps"]
        positions = {step["name"]: index for index, step in enumerate(deploy_steps)}
        rebind_name = "Rebind five publisher inputs before interpretation or credentials"
        freshness_name = "Reconfirm public main at exact source revision without credentials"
        self.assertLess(
            positions[rebind_name],
            positions["Install pinned Hugging Face client without repository credentials"],
        )
        self.assertLess(
            positions[rebind_name],
            positions["Classify publisher-environment failure before credential materialization"],
        )
        self.assertLess(
            positions[rebind_name],
            positions["Publish exact bundle with only the Hugging Face credential"],
        )
        self.assertLess(
            positions["Install pinned Hugging Face client without repository credentials"],
            positions[freshness_name],
        )
        self.assertLess(
            positions[freshness_name],
            positions["Publish exact bundle with only the Hugging Face credential"],
        )
        rebind_step = deploy_steps[positions[rebind_name]]
        self.assertNotIn("HF_TOKEN", rebind_step["env"])
        self.assertNotIn("python", rebind_step["run"])
        self.assertNotRegex(
            rebind_step["run"],
            r"(?mi)(?:^|[;&|])\s*(?:pip3?|python(?:3(?:\.\d+)?)?\s+-m\s+pip)\b",
        )
        for step_name in (
            "Set up exact Python",
            "Install pinned Hugging Face client without repository credentials",
            "Classify publisher-environment failure before credential materialization",
            freshness_name,
            "Classify public-main freshness failure before mutation",
            "Publish exact bundle with only the Hugging Face credential",
        ):
            self.assertIn(
                "publisher-rebind.outcome == 'success'",
                deploy_steps[positions[step_name]].get("if", ""),
            )
        freshness_step = deploy_steps[positions[freshness_name]]
        self.assertEqual(
            freshness_step["env"],
            {"GITHUB_TOKEN": "", "GH_TOKEN": "", "HF_TOKEN": ""},
        )
        self.assertIn("fresh-main", freshness_step["run"])
        self.assertIn("/usr/bin/env -i", freshness_step["run"])
        freshness_isolated = freshness_step["run"].split("/usr/bin/env -i", 1)[1].split(
            '"$PUBLISHER_PYTHON"', 1
        )[0]
        self.assertEqual(
            set(re.findall(r"(?m)^\s*([A-Z][A-Z0-9_]*)=", freshness_isolated)),
            {"HOME", "HF_HOME", "XDG_CACHE_HOME", "PATH", "LANG", "LC_ALL", "PYTHONIOENCODING"},
        )
        for forbidden in ("ACTIONS_", "GITHUB_TOKEN", "GH_TOKEN", "HF_TOKEN"):
            self.assertNotIn(forbidden, freshness_isolated)
        self.assertIn(
            "publisher-freshness.outcome == 'success'",
            deploy_steps[positions[
                "Publish exact bundle with only the Hugging Face credential"
            ]]["if"],
        )
        publish_run = deploy_steps[positions[
            "Publish exact bundle with only the Hugging Face credential"
        ]]["run"]
        self.assertIn("/usr/bin/env -i", publish_run)
        isolated = publish_run.split("/usr/bin/env -i", 1)[1].split(
            '"$PUBLISHER_PYTHON"', 1
        )[0]
        assignments = set(
            re.findall(r"(?m)^\s*([A-Z][A-Z0-9_]*)=", isolated)
        )
        self.assertEqual(
            assignments,
            {
                "HOME",
                "HF_HOME",
                "XDG_CACHE_HOME",
                "PATH",
                "LANG",
                "LC_ALL",
                "PYTHONIOENCODING",
                "HF_TOKEN",
            },
        )
        for forbidden in (
            "ACTIONS_",
            "GITHUB_ENV",
            "GITHUB_OUTPUT",
            "GITHUB_PATH",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        ):
            self.assertNotIn(forbidden, isolated)

        artifact_steps = [
            step
            for job in jobs.values()
            for step in job.get("steps", [])
            if str(step.get("uses", "")).startswith(
                ("actions/upload-artifact@", "actions/download-artifact@")
            )
        ]
        self.assertGreater(len(artifact_steps), 0)
        for step in artifact_steps:
            artifact_name = step["with"]["name"]
            if "actions/upload-artifact@" in step["uses"]:
                self.assertIn("${{ github.sha }}", artifact_name)
                self.assertIn("${{ github.run_attempt }}", artifact_name)
            else:
                self.assertTrue(artifact_name.startswith("${{ needs."))

        measurement_rebind = measure_steps["measurement-rebind"]
        self.assertEqual(
            set(measurement_rebind["env"]),
            {
                "EXPECTED_PUBLISHER_SCRIPT_SHA256",
                "EXPECTED_PUBLISHER_LOCK_SHA256",
                "EXPECTED_PUBLISHER_CONFIG_SHA256",
                "EXPECTED_AUTHORIZATION_SHA256",
                "EXPECTED_BUNDLE_MANIFEST_SHA256",
                "GITHUB_TOKEN",
                "GH_TOKEN",
                "HF_TOKEN",
            },
        )
        self.assertEqual(measurement_rebind["run"].count("require_digest \"$EXPECTED_"), 5)
        self.assertIn(
            "steps.measurement-rebind.outcome == 'success'",
            measure_steps["measurement-publisher-evidence"]["if"],
        )
        self.assertIn(
            "steps.measurement-environment.outcome == 'success'",
            measure_steps["measurement"]["if"],
        )

        outcome_step = attest_steps["workflow-outcome"]
        self.assertIs(outcome_step["continue-on-error"], True)
        self.assertIn("terminal_synthesizer_bootstrap", outcome_step["run"])
        self.assertIn("hf-workflow-stage-failure.json", outcome_step["run"])
        for step in jobs["attest"]["steps"]:
            if step.get("id") == "oidc":
                continue
            self.assertEqual(step.get("env", {}).get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"), "")
            self.assertEqual(step.get("env", {}).get("ACTIONS_ID_TOKEN_REQUEST_URL"), "")
        self.assertIn("publisher_executable_rebind", SCRIPT.read_text(encoding="utf-8"))

    def test_rebind_failure_is_terminal_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt.json"
            failure = root / "workflow-failure.json"
            result = MODULE.synthesize_workflow_outcome(
                SOURCE_SHA,
                root / "missing-result.json",
                root / "missing-measurement.json",
                root / "missing-mutation-failure.json",
                root / "missing-partial.json",
                receipt,
                failure,
                "skipped",
                "skipped",
                "skipped",
                "skipped",
                publisher_rebind_outcome="failure",
            )
            self.assertEqual(
                result["failure_stage"], "publisher_executable_rebind"
            )
            self.assertFalse(receipt.exists())
            self.assertEqual(failure.read_bytes(), MODULE.canonical_json(result))

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
            repository = MODULE.load_config()["source_repository"]
            commit_url = (
                f"{MODULE.PUBLIC_GITHUB_API_ROOT}/repos/{repository}/git/commits/{SOURCE_SHA}"
            )

            def public_main_response(url: str) -> dict:
                if url == commit_url:
                    events.append("github-commit")
                    return {"sha": SOURCE_SHA, "url": commit_url}
                events.append("github-main")
                return {
                    "ref": "refs/heads/main",
                    "object": {
                        "type": "commit",
                        "sha": SOURCE_SHA,
                        "url": commit_url,
                    },
                }

            with mock.patch.dict(
                os.environ, {"HF_TOKEN": "test-token"}, clear=False
            ), mock.patch.dict(
                sys.modules, {"huggingface_hub": fake_hub}
            ), mock.patch.object(
                MODULE, "_request_json", side_effect=public_main_response
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
                    freshness_output_path=root / "github-main-freshness.json",
                )
            assert api.upload_kwargs is not None
            self.assertEqual(api.upload_kwargs["parent_commit"], PARENT_SHA)
            self.assertEqual(api.upload_kwargs["delete_patterns"], "*")
            self.assertEqual(Path(api.upload_kwargs["folder_path"]), bundle)
            self.assertEqual(result["previous_hf_revision"], PARENT_SHA)
            self.assertEqual(result["hf_revision"], TARGET_SHA)
            self.assertEqual(
                events, ["parent", "github-commit", "github-main", "upload"]
            )
            self.assertEqual(result["authorization"], governed_merge_evidence())
            self.assertFalse(failure_path.exists())

    def test_final_freshness_failure_removes_stale_evidence_before_upload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            failure_path = root / "failure.json"
            freshness_path = root / "github-main-freshness.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            authorization_path = write_authorization(root)
            freshness_path.write_bytes(
                MODULE.canonical_json({"status": "PUBLIC_MAIN_FRESH"})
            )
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
                "require_public_main_fresh",
                side_effect=MODULE.ContractError("public main moved"),
            ):
                with self.assertRaises(MODULE.ContractError):
                    MODULE.deploy_bundle(
                        bundle,
                        SOURCE_SHA,
                        result_path,
                        authorization_path=authorization_path,
                        failure_output_path=failure_path,
                        freshness_output_path=freshness_path,
                    )
            self.assertFalse(freshness_path.exists())
            self.assertIsNone(api.upload_kwargs)
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(failure["status"], "FAILED_BEFORE_MUTATION")
            self.assertFalse(failure["upload_call_entered"])

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
                MODULE, "require_public_main_fresh", return_value={}
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
                        freshness_output_path=root / "github-main-freshness.json",
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
                        freshness_output_path=root / "github-main-freshness.json",
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
                MODULE, "require_public_main_fresh", return_value={}
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
                        freshness_output_path=root / "github-main-freshness.json",
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
                        freshness_output_path=root / "github-main-freshness.json",
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

        secret = "hf_secret/with+chars"
        representations = (
            f"Authorization: Bearer {secret}",
            f"headers={{'Authorization': 'Bearer {secret}'}}",
            "https://example.invalid/read?token=" + urllib.parse.quote(secret, safe=""),
            f"api_key={secret}",
        )
        for representation in representations:
            with self.subTest(representation=representation):
                redacted = MODULE._sanitized_diagnostic(
                    RuntimeError(representation), (secret,)
                )
                self.assertNotIn(secret, redacted)
                self.assertNotIn(urllib.parse.quote(secret, safe=""), redacted)
                self.assertIn("<redacted>", redacted)

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
            (
                {"authorization_evidence_outcome": "failure"},
                "governance_authorization_evidence",
            ),
            ({"bundle_outcome": "failure"}, "publisher_bundle"),
            ({"publisher_input_outcome": "failure"}, "publisher_input_staging"),
            (
                {"publisher_digests_outcome": "failure"},
                "publisher_input_digest_binding",
            ),
            (
                {"publisher_input_evidence_outcome": "failure"},
                "publisher_input_evidence_upload",
            ),
            (
                {"publisher_input_download_outcome": "failure"},
                "publisher_input_download",
            ),
            ({"publisher_environment_outcome": "failure"}, "publisher_environment"),
            ({"publisher_freshness_outcome": "failure"}, "publisher_freshness"),
            ({"publisher_evidence_outcome": "failure"}, "publisher_evidence_upload"),
            (
                {"publisher_evidence_download_outcome": "failure"},
                "publisher_evidence_download",
            ),
            (
                {"measurement_evidence_download_outcome": "failure"},
                "measurement_evidence_download",
            ),
            ({"measurement_hardening_outcome": "failure"}, "measurement_hardening"),
            ({"measurement_input_outcome": "failure"}, "measurement_input"),
            (
                {"measurement_rebind_outcome": "failure"},
                "measurement_executable_rebind",
            ),
            (
                {"measurement_publisher_evidence_outcome": "failure"},
                "measurement_publisher_evidence_download",
            ),
            (
                {"measurement_environment_outcome": "failure"},
                "measurement_environment",
            ),
            (
                {"attestation_hardening_outcome": "failure"},
                "attestation_hardening",
            ),
            (
                {"attestation_checkout_outcome": "failure"},
                "attestation_checkout",
            ),
            (
                {"attestation_environment_outcome": "failure"},
                "attestation_environment",
            ),
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


class WorkflowBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / "hf-static-space.yml").read_text(
                encoding="utf-8"
            )
        )

    def test_every_artifact_channel_is_unique_per_run_attempt(self) -> None:
        artifact_steps = [
            (job_id, step)
            for job_id, job in self.workflow["jobs"].items()
            for step in job.get("steps", [])
            if "actions/upload-artifact@" in str(step.get("uses", ""))
            or "actions/download-artifact@" in str(step.get("uses", ""))
        ]
        self.assertEqual(len(artifact_steps), 11)
        uploads = [
            (job_id, step)
            for job_id, step in artifact_steps
            if "actions/upload-artifact@" in str(step.get("uses", ""))
        ]
        downloads = {
            (job_id, step["name"]): step["with"]["name"]
            for job_id, step in artifact_steps
            if "actions/download-artifact@" in str(step.get("uses", ""))
        }
        self.assertEqual(len(uploads), 6)
        for job_id, step in uploads:
            with self.subTest(job=job_id, step=step["name"]):
                self.assertIn(
                    "${{ github.run_attempt }}",
                    step["with"]["name"],
                )
        self.assertEqual(
            downloads,
            {
                (
                    "deploy",
                    "Download exact authorized publisher input",
                ): "${{ needs.authorize.outputs.publisher-input-artifact-name }}",
                (
                    "measure",
                    "Download exact authorized publisher input",
                ): "${{ needs.authorize.outputs.publisher-input-artifact-name }}",
                (
                    "measure",
                    "Download exact publisher outcome",
                ): "${{ needs.deploy.outputs.publication-artifact-name }}",
                (
                    "attest",
                    "Download exact publisher outcome",
                ): "${{ needs.deploy.outputs.publication-artifact-name }}",
                (
                    "attest",
                    "Download exact public measurement",
                ): "${{ needs.measure.outputs.measurement-artifact-name }}",
            },
        )

    def test_attestation_downloads_reject_missing_producer_channels(self) -> None:
        steps = {
            step["name"]: step
            for step in self.workflow["jobs"]["attest"]["steps"]
        }
        self.assertEqual(
            steps["Download exact publisher outcome"]["if"],
            "needs.deploy.outputs.publication-artifact-name != ''",
        )
        self.assertEqual(
            steps["Download exact public measurement"]["if"],
            "needs.measure.outputs.measurement-artifact-name != ''",
        )

    def test_attestation_downloads_preserve_named_failure_evidence(self) -> None:
        steps = {
            step["name"]: step
            for step in self.workflow["jobs"]["attest"]["steps"]
        }
        expected_channels = {
            "Download exact publisher outcome": (
                "needs.deploy.outputs.publication-artifact-name"
            ),
            "Download exact public measurement": (
                "needs.measure.outputs.measurement-artifact-name"
            ),
        }
        for name, channel in expected_channels.items():
            with self.subTest(step=name):
                step = steps[name]
                self.assertEqual(step["if"], f"{channel} != ''")
                self.assertEqual(step["with"]["name"], "${{ " + channel + " }}")
                self.assertNotIn(".result", step["if"])
                self.assertIs(step["continue-on-error"], True)

    def test_publish_path_is_bound_without_an_unset_step_environment(self) -> None:
        steps = {
            step["name"]: step
            for step in self.workflow["jobs"]["deploy"]["steps"]
        }
        environment = steps[
            "Install pinned Hugging Face client without repository credentials"
        ]
        self.assertEqual(
            environment["env"]["PUBLISHER_VENV"],
            "${{ runner.temp }}/hf-publisher-venv",
        )
        for name in (
            "Reconfirm public main at exact source revision without credentials",
            "Publish exact bundle with only the Hugging Face credential",
        ):
            with self.subTest(step=name):
                command = steps[name]["run"]
                self.assertIn(
                    'PATH="$RUNNER_TEMP/hf-publisher-venv/bin:/usr/bin:/bin"',
                    command,
                )
                self.assertNotIn('PATH="$PUBLISHER_VENV/bin', command)

    def test_terminal_synthesis_preserves_authorize_stage_outcomes(self) -> None:
        steps = {
            step["name"]: step
            for step in self.workflow["jobs"]["attest"]["steps"]
        }
        synthesis = "\n".join(
            (
                steps[
                    "Synthesize final receipt or exact workflow-stage failure"
                ]["run"],
                steps["Synthesize terminal artifact-upload failure"]["run"],
            )
        )
        terminal = steps["Require terminal governed success"]["run"]
        outcomes = {
            "--bundle-outcome": "${{ needs.authorize.outputs.bundle-outcome }}",
            "--publisher-input-outcome": (
                "${{ needs.authorize.outputs.publisher-input-outcome }}"
            ),
            "--publisher-digests-outcome": (
                "${{ needs.authorize.outputs.publisher-digests-outcome }}"
            ),
            "--publisher-input-evidence-outcome": (
                "${{ needs.authorize.outputs.publisher-input-evidence-outcome }}"
            ),
            "--publisher-input-download-outcome": (
                "${{ needs.deploy.outputs.publisher-input-outcome }}"
            ),
        }
        for argument, expression in outcomes.items():
            with self.subTest(argument=argument):
                self.assertEqual(
                    synthesis.count(f'{argument} "{expression}"'),
                    2,
                )
                self.assertIn(f'test "{expression}" = "success"', terminal)

        publish = steps.get("Publish exact bundle with only the Hugging Face credential")
        if publish is None:
            publish = {
                step["name"]: step
                for step in self.workflow["jobs"]["deploy"]["steps"]
            }["Publish exact bundle with only the Hugging Face credential"]
        self.assertIn(
            '--freshness-output "$RUNNER_TEMP/publication-evidence/github-main-freshness.json"',
            publish["run"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
