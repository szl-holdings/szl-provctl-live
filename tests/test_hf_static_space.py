from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "hf_static_space.py"
SPEC = importlib.util.spec_from_file_location("hf_static_space", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SOURCE_SHA = "a" * 40


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

    def test_workflow_never_publishes_a_pull_request_or_manual_dispatch(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "hf-static-space.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pull_request:", workflow)
        self.assertIn("branches: [main]", workflow)
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("format('pr-{0}', github.event.pull_request.number)", workflow)
        self.assertIn("permission-administration: read", workflow)

    def test_workflow_reauthorizes_before_hf_credential_use(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "hf-static-space.yml").read_text(
            encoding="utf-8"
        )
        guard = workflow.index("Reauthorize exact governed main without HF credentials")
        token = workflow.index("HF_TOKEN: ${{ secrets.HF_TOKEN }}")
        self.assertLess(guard, token)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", workflow)
        self.assertIn("actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97", workflow)
        self.assertIn("huggingface_hub==1.19.0", workflow)

    def test_deployer_has_exact_main_and_optimistic_lock_guards(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        deploy = source[source.index("def deploy_bundle(") : source.index("def _hf_json(")]
        self.assertLess(
            deploy.index("require_governed_main(source_sha, config_path)"),
            deploy.index('token = os.environ.get("HF_TOKEN", "")'),
        )
        self.assertIn("parent_commit=before_sha", deploy)
        self.assertIn('delete_patterns="*"', deploy)
        for rule in ("pull_request", "non_fast_forward", "required_linear_history"):
            self.assertIn(rule, source)
        self.assertIn('detail or {}).get("bypass_actors") == []', source)

    def test_guard_requires_applicable_inherited_no_bypass_rules(self) -> None:
        ruleset_id = 17630223
        active_rules = [
            {
                "type": rule,
                "ruleset_source_type": "Organization",
                "ruleset_source": "szl-holdings",
                "ruleset_id": ruleset_id,
            }
            for rule in ("pull_request", "non_fast_forward", "required_linear_history")
        ]
        detail = {
            "id": ruleset_id,
            "enforcement": "active",
            "source_type": "Organization",
            "source": "szl-holdings",
            "bypass_actors": [],
            "current_user_can_bypass": "never",
        }
        responses = [
            {"default_branch": "main"},
            {"commit": {"sha": SOURCE_SHA}},
            active_rules,
            detail,
        ]
        environment = {
            "GITHUB_REPOSITORY": "szl-holdings/szl-provctl-live",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_TOKEN": "app-token",
        }
        with patch.dict(os.environ, environment, clear=False), patch.object(
            MODULE, "_request_json", side_effect=responses
        ) as request_json:
            result = MODULE.require_governed_main(SOURCE_SHA)

        self.assertEqual(result["ruleset_ids"], [ruleset_id])
        self.assertTrue(request_json.call_args_list[2].args[0].endswith("/rules/branches/main"))

        detail["bypass_actors"] = [{"actor_id": 1}]
        with patch.dict(os.environ, environment, clear=False), patch.object(
            MODULE,
            "_request_json",
            side_effect=[responses[0], responses[1], active_rules, detail],
        ):
            with self.assertRaisesRegex(MODULE.ContractError, "no-bypass"):
                MODULE.require_governed_main(SOURCE_SHA)

    def test_public_static_origin_and_bytes_are_exact(self) -> None:
        self.assertEqual(
            MODULE._static_origin("SZLHOLDINGS/receipt-chain-live"),
            "https://szlholdings-receipt-chain-live.hf.space",
        )
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("body == expected_ui", source)
        self.assertIn("provenance_body == expected_provenance", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
