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
        "id": 7,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}
        },
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews_on_push": False,
                    "require_code_owner_review": False,
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": True,
                },
            },
            {"type": "non_fast_forward"},
            {"type": "required_linear_history"},
            {"type": "required_signatures"},
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": "validate-static-space", "integration_id": 15368},
                        {"context": "DCO", "integration_id": 15368},
                    ],
                },
            },
        ],
    }


def guard_responder(detail: dict):
    repository = MODULE.load_config()["source_repository"]

    def respond(url: str, token: str = "") -> object:
        if token != "github-test-token":
            raise AssertionError("guard omitted its GitHub credential")
        if url.endswith(f"/repos/{repository}"):
            return {"default_branch": "main"}
        if url.endswith(f"/repos/{repository}/branches/main"):
            return {"commit": {"sha": SOURCE_SHA}}
        if url.endswith(f"/repos/{repository}/rulesets?includes_parents=true"):
            return [{"id": 7, "target": "branch", "enforcement": "active"}]
        if url.endswith(f"/repos/{repository}/rulesets/7"):
            return detail
        raise AssertionError(f"unexpected guard URL: {url}")

    return respond


class FakeHfApi:
    def __init__(self, stale: bool = False) -> None:
        self.stale = stale
        self.upload_kwargs: dict | None = None

    def space_info(self, target: str, token: str):
        return SimpleNamespace(sha=PARENT_SHA)

    def upload_folder(self, **kwargs):
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
        self.assertEqual(result["ruleset_ids"], [7])
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
                        with self.assertRaisesRegex(MODULE.ContractError, "lacks one exact"):
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
                with self.assertRaisesRegex(MODULE.ContractError, "lacks one exact"):
                    MODULE.require_governed_main(SOURCE_SHA)

    def test_guard_api_error_fails_closed(self) -> None:
        with mock.patch.object(
            MODULE.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("offline"),
        ):
            with self.assertRaisesRegex(MODULE.ContractError, "JSON request failed closed"):
                MODULE._request_json("https://api.github.test/repos/example/repo", "token")

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

    def test_deploy_uses_parent_lock_and_full_tree_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            result_path = root / "result.json"
            MODULE.build_bundle(bundle, SOURCE_SHA)
            api = FakeHfApi()
            fake_hub = SimpleNamespace(HfApi=lambda token: api)
            authorization = {"status": "AUTHORIZED_EXACT_PROTECTED_MAIN"}
            with mock.patch.dict(os.environ, {"HF_TOKEN": "test-token"}, clear=False):
                with mock.patch.dict(sys.modules, {"huggingface_hub": fake_hub}):
                    with mock.patch.object(
                        MODULE, "require_governed_main", return_value=authorization
                    ):
                        result = MODULE.deploy_bundle(bundle, SOURCE_SHA, result_path)
            assert api.upload_kwargs is not None
            self.assertEqual(api.upload_kwargs["parent_commit"], PARENT_SHA)
            self.assertEqual(api.upload_kwargs["delete_patterns"], "*")
            self.assertEqual(Path(api.upload_kwargs["folder_path"]), bundle)
            self.assertEqual(result["previous_hf_revision"], PARENT_SHA)
            self.assertEqual(result["hf_revision"], TARGET_SHA)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
