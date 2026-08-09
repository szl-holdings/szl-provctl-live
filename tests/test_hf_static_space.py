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


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "hf_static_space.py"
SPEC = importlib.util.spec_from_file_location("hf_static_space", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SOURCE_SHA = "a" * 40
PARENT_SHA = "b" * 40
TARGET_SHA = "c" * 40


def strong_ruleset() -> dict:
    return {
        "id": MODULE.GOVERNED_RULESET_ID,
        "name": MODULE.GOVERNED_RULESET_NAME,
        "source": MODULE.GOVERNED_RULESET_SOURCE,
        "source_type": "Organization",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "repository_id": {
                "repository_ids": list(MODULE.TARGET_REPOSITORY_IDS.values())
            },
            "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []},
        },
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": False,
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": True,
                    "required_reviewers": [],
                    "allowed_merge_methods": ["squash", "rebase"],
                },
            },
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
            {"type": "required_signatures"},
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": "validate-static-space", "integration_id": 15368},
                        {"context": "DCO", "integration_id": 15368},
                    ],
                },
            },
        ],
    }


def inherited_rules(detail: dict) -> list[dict]:
    return [
        {
            **copy.deepcopy(row),
            "ruleset_id": MODULE.GOVERNED_RULESET_ID,
            "ruleset_source": MODULE.GOVERNED_RULESET_SOURCE,
            "ruleset_source_type": "Organization",
        }
        for row in detail["rules"]
    ]


def guard_responder(
    detail: dict,
    *,
    effective: object | None = None,
    summary: object | None = None,
    metadata: object | None = None,
):
    repository = MODULE.load_config()["source_repository"]
    repository_id = MODULE.TARGET_REPOSITORY_IDS[repository]
    if effective is None:
        effective = inherited_rules(detail)
    if summary is None:
        summary = [
            {
                "id": MODULE.GOVERNED_RULESET_ID,
                "name": MODULE.GOVERNED_RULESET_NAME,
                "source": MODULE.GOVERNED_RULESET_SOURCE,
                "source_type": "Organization",
                "target": "branch",
                "enforcement": "active",
            }
        ]
    if metadata is None:
        metadata = {
            "id": repository_id,
            "full_name": repository,
            "default_branch": "main",
        }

    def respond(url: str, token: str = "") -> object:
        if token != "github-test-token":
            raise AssertionError("guard omitted its GitHub credential")
        if url.endswith(f"/repos/{repository}"):
            return metadata
        if url.endswith(f"/repos/{repository}/branches/main"):
            return {"commit": {"sha": SOURCE_SHA}}
        if url.endswith(f"/repos/{repository}/rulesets?includes_parents=true"):
            return summary
        if url.endswith(
            f"/repos/{repository}/rulesets/{MODULE.GOVERNED_RULESET_ID}"
        ):
            return detail
        if url.endswith(f"/repos/{repository}/rules/branches/main"):
            return effective
        raise AssertionError(f"unexpected guard URL: {url}")

    return respond


class FakeHfApi:
    def __init__(self, stale: bool = False, events: list[str] | None = None) -> None:
        self.stale = stale
        self.events = events if events is not None else []
        self.upload_kwargs: dict | None = None

    def space_info(self, target: str, token: str):
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
        "authorization": {"status": "AUTHORIZED_EXACT_PROTECTED_MAIN"},
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

    def test_guard_authorizes_solo_exact_default_policy(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch.object(
                MODULE, "_request_json", side_effect=guard_responder(strong_ruleset())
            ):
                result = MODULE.require_governed_main(SOURCE_SHA)
        self.assertEqual(result["status"], "AUTHORIZED_EXACT_PROTECTED_MAIN")
        self.assertEqual(result["ruleset_ids"], [MODULE.GOVERNED_RULESET_ID])
        self.assertEqual(
            result["repository_id"], MODULE.TARGET_REPOSITORY_IDS[repository]
        )
        self.assertEqual(result["required_status_contexts"], ["DCO", "validate-static-space"])

    def test_guard_rejects_weak_rulesets(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        variants: dict[str, dict] = {}
        no_signatures = strong_ruleset()
        no_signatures["rules"] = [
            row for row in no_signatures["rules"] if row["type"] != "required_signatures"
        ]
        variants["no signatures"] = no_signatures
        no_dco = strong_ruleset()
        checks = next(
            row for row in no_dco["rules"] if row["type"] == "required_status_checks"
        )
        checks["parameters"]["required_status_checks"] = [
            {"context": "validate-static-space", "integration_id": 15368}
        ]
        variants["no DCO"] = no_dco
        excluded_main = strong_ruleset()
        excluded_main["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
        variants["excluded main"] = excluded_main
        with mock.patch.dict(os.environ, environment, clear=False):
            for label, detail in variants.items():
                with self.subTest(label=label):
                    with mock.patch.object(
                        MODULE, "_request_json", side_effect=guard_responder(detail)
                    ):
                        with self.assertRaisesRegex(
                            MODULE.ContractError, "does not match the exact"
                        ):
                            MODULE.require_governed_main(SOURCE_SHA)

    def test_guard_rejects_substitute_local_or_ineffective_ruleset(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        local = strong_ruleset()
        local["source"] = repository
        local["source_type"] = "Repository"
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch.object(
                MODULE, "_request_json", side_effect=guard_responder(local)
            ):
                with self.assertRaisesRegex(MODULE.ContractError, "does not match the exact"):
                    MODULE.require_governed_main(SOURCE_SHA)
            with mock.patch.object(
                MODULE,
                "_request_json",
                side_effect=guard_responder(strong_ruleset(), effective=[]),
            ):
                with self.assertRaisesRegex(MODULE.ContractError, "not fully effective"):
                    MODULE.require_governed_main(SOURCE_SHA)
            wrong_metadata = {
                "id": 1,
                "full_name": repository,
                "default_branch": "main",
            }
            with mock.patch.object(
                MODULE,
                "_request_json",
                side_effect=guard_responder(
                    strong_ruleset(), metadata=wrong_metadata
                ),
            ):
                with self.assertRaisesRegex(MODULE.ContractError, "identity"):
                    MODULE.require_governed_main(SOURCE_SHA)

    def test_guard_rejects_status_context_bound_to_wrong_integration(self) -> None:
        repository = MODULE.load_config()["source_repository"]
        environment = {
            "GITHUB_REPOSITORY": repository,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "github-test-token",
            "GITHUB_API_URL": "https://api.github.test",
        }
        detail = strong_ruleset()
        checks = next(
            row for row in detail["rules"] if row["type"] == "required_status_checks"
        )
        checks["parameters"]["required_status_checks"][1]["integration_id"] = 99
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch.object(
                MODULE, "_request_json", side_effect=guard_responder(detail)
            ):
                with self.assertRaisesRegex(MODULE.ContractError, "does not match the exact"):
                    MODULE.require_governed_main(SOURCE_SHA)

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
        with mock.patch.dict(os.environ, environment, clear=False):
            with mock.patch.object(MODULE, "_request_json") as request_json:
                with self.assertRaisesRegex(MODULE.ContractError, "GITHUB_TOKEN is required"):
                    MODULE.require_governed_main(SOURCE_SHA)
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
        workflow = (
            ROOT / ".github" / "workflows" / "hf-static-space.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("  dco:\n    name: DCO\n", workflow)
        self.assertIn('python-version: "3.12.13"', workflow)
        self.assertNotIn('python-version: "3.12"\n', workflow)
        self.assertIn("needs: [validate, dco]", workflow)
        self.assertIn(
            "format('pr-{0}', github.event.pull_request.number) || 'production'",
            workflow,
        )
        self.assertIn(
            "actions/create-github-app-token@"
            "bcd2ba49218906704ab6c1aa796996da409d3eb1",
            workflow,
        )
        self.assertIn("permission-administration: read", workflow)
        self.assertIn("permission-contents: read", workflow)
        self.assertIn('test -n "$GOVERNANCE_TOKEN"', workflow)
        token = workflow.index("Mint least-privilege governed ruleset reader")
        guard = workflow.index("Reauthorize exact governed main without HF credentials")
        hf_credential = workflow.index("HF_TOKEN: ${{ secrets.HF_TOKEN }}")
        self.assertLess(token, guard)
        self.assertLess(guard, hf_credential)
        self.assertIn(
            "GITHUB_TOKEN: ${{ steps.governance-token.outputs.token }}",
            workflow,
        )
        self.assertNotIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn('python -I -m venv "$PUBLISHER_VENV"', workflow)
        self.assertIn('test ! -e "$PUBLISHER_VENV"', workflow)
        self.assertIn("--require-hashes --only-binary=:all: --ignore-installed", workflow)
        self.assertIn('"$PUBLISHER_PYTHON" -I scripts/hf_static_space.py deploy', workflow)
        self.assertIn('"$PUBLISHER_PYTHON" -I scripts/hf_static_space.py attest', workflow)
        self.assertIn("hf-publication-partial.json", workflow)

    def test_deploy_uses_parent_lock_and_full_tree_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            events: list[str] = []
            api = FakeHfApi(events=events)
            fake_hub = SimpleNamespace(HfApi=lambda token: api)
            authorization = {"status": "AUTHORIZED_EXACT_PROTECTED_MAIN"}

            def authorize(*_args):
                events.append("guard")
                return authorization

            with mock.patch.dict(os.environ, {"HF_TOKEN": "test-token"}, clear=False):
                with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hub}):
                    with mock.patch.object(
                        MODULE, "require_governed_main", side_effect=authorize
                    ):
                        result = MODULE.deploy_bundle(bundle, SOURCE_SHA, result_path)
            assert api.upload_kwargs is not None
            self.assertEqual(api.upload_kwargs["parent_commit"], PARENT_SHA)
            self.assertEqual(api.upload_kwargs["delete_patterns"], "*")
            self.assertEqual(Path(api.upload_kwargs["folder_path"]), bundle)
            self.assertEqual(result["previous_hf_revision"], PARENT_SHA)
            self.assertEqual(result["hf_revision"], TARGET_SHA)
            self.assertEqual(events, ["parent", "guard", "upload"])

    def test_deploy_stale_parent_fails_without_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            api = FakeHfApi(stale=True)
            fake_hub = SimpleNamespace(HfApi=lambda token: api)
            with mock.patch.dict(os.environ, {"HF_TOKEN": "test-token"}, clear=False):
                with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hub}):
                    with mock.patch.object(
                        MODULE,
                        "require_governed_main",
                        return_value={"status": "AUTHORIZED_EXACT_PROTECTED_MAIN"},
                    ):
                        with self.assertRaisesRegex(RuntimeError, "parent commit changed"):
                            MODULE.deploy_bundle(bundle, SOURCE_SHA, result_path)
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
        with mock.patch.object(MODULE, "_public_response", side_effect=responses):
            actual = MODULE._fetch_public_index(origin, SOURCE_SHA)
        self.assertEqual(actual, expected)
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
                MODULE._fetch_public_index(origin, SOURCE_SHA)
        with mock.patch.object(
            MODULE, "_public_response", return_value=(200, b"unexpected", None)
        ):
            with self.assertRaisesRegex(MODULE.ContractError, "expected one 302"):
                MODULE._fetch_public_index(origin, SOURCE_SHA)

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
            write_deploy_result(bundle, result_path)
            events: list[str] = []

            def hf_json(url: str):
                if "/tree/" in url:
                    events.append("tree")
                    return live_tree(bundle)
                events.append("runtime")
                return {"sha": TARGET_SHA, "runtime": {"stage": "RUNNING"}}

            def public_index(*_args):
                events.append("index")
                return (bundle / "index.html").read_bytes()

            def provenance(*_args):
                events.append("provenance")
                return 200, (bundle / "SPACE_PROVENANCE.json").read_bytes(), None

            def authorize(*_args):
                events.append("guard")
                return {"status": "AUTHORIZED_EXACT_PROTECTED_MAIN"}

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
                            )
            self.assertEqual(attestation["status"], "MEASURED")
            self.assertEqual(events, ["runtime", "tree", "index", "provenance", "guard"])
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
            write_deploy_result(bundle, result_path)

            def hf_json(url: str):
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
                                )
            partial = json.loads(partial_path.read_text(encoding="utf-8"))
            self.assertEqual(partial["status"], "PARTIAL")
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
                    )
            partial = json.loads(partial_path.read_text(encoding="utf-8"))
            self.assertEqual(partial["hf_revision"], TARGET_SHA)
            self.assertEqual(partial["failure_stage"], "runtime_readback")
            self.assertNotIn("raw-secret", partial["diagnostic"])
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
