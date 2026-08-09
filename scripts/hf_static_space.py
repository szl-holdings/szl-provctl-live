#!/usr/bin/env python3
"""Build, publish, and attest an exact protected-main static Space bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / ".hf-space.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_RULE_TYPES = {"pull_request", "non_fast_forward", "required_linear_history"}
TERMINAL_STAGES = {"BUILD_ERROR", "CONFIG_ERROR", "RUNTIME_ERROR"}
UA = "szl-hf-static-space/1.0"


class ContractError(RuntimeError):
    """The release request does not satisfy the governed publication contract."""


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def git_blob_sha1(value: bytes) -> str:
    digest = hashlib.sha1()
    digest.update(b"blob " + str(len(value)).encode("ascii") + b"\0" + value)
    return digest.hexdigest()


def exact_sha(value: str, label: str = "source revision") -> str:
    normalized = str(value or "").lower()
    if not HEX40.fullmatch(normalized):
        raise ContractError(f"{label} must be an exact lowercase 40-character SHA")
    return normalized


def safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ContractError(f"unsafe bundle path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
        raise ContractError(f"unsafe bundle path: {value!r}")
    return str(path)


def load_config(path: Path = DEFAULT_CONFIG) -> dict[str, object]:
    config = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "schema",
        "source_repository",
        "target",
        "files",
        "allowed_hf_extras",
        "smoke_paths",
        "wait_running_seconds",
    }
    if set(config) != required or config["schema"] != "szl.hf-static-space/v1":
        raise ContractError("static Space configuration does not match v1")
    source = config["source_repository"]
    target = config["target"]
    if not isinstance(source, str) or not source.startswith("szl-holdings/"):
        raise ContractError("source_repository must be an SZL GitHub repository")
    if not isinstance(target, str) or target != "SZLHOLDINGS/" + source.split("/", 1)[1]:
        raise ContractError("target must match the source repository name")
    files = config["files"]
    if not isinstance(files, list) or not files:
        raise ContractError("files must be a non-empty list")
    normalized = [safe_relative(item) for item in files]
    if normalized != sorted(set(normalized)):
        raise ContractError("files must be sorted and unique")
    if normalized != ["LICENSE", "README.md", "index.html"]:
        raise ContractError("static release must close LICENSE, README.md, and index.html")
    extras = config["allowed_hf_extras"]
    if not isinstance(extras, list) or [safe_relative(item) for item in extras] != [
        ".gitattributes"
    ]:
        raise ContractError("only the Hugging Face-managed .gitattributes extra is allowed")
    smoke = config["smoke_paths"]
    if smoke != ["/", "/SPACE_PROVENANCE.json"]:
        raise ContractError("smoke paths must close the UI and source provenance")
    wait = config["wait_running_seconds"]
    if not isinstance(wait, int) or wait < 60 or wait > 1800:
        raise ContractError("wait_running_seconds must be between 60 and 1800")
    return config


def source_file(relative: str) -> Path:
    path = ROOT.joinpath(*PurePosixPath(safe_relative(relative)).parts)
    if path.is_symlink() or not path.is_file():
        raise ContractError(f"tracked release file is missing or symbolic: {relative}")
    if ROOT.resolve() not in path.resolve().parents:
        raise ContractError(f"release file escapes repository root: {relative}")
    return path


def _manifest_entries(bundle: Path, paths: list[str]) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for relative in sorted(paths):
        path = bundle.joinpath(*PurePosixPath(relative).parts)
        data = path.read_bytes()
        entries.append(
            {
                "path": relative,
                "bytes": len(data),
                "git_blob_sha1": git_blob_sha1(data),
                "sha256": sha256_bytes(data),
            }
        )
    return entries


def build_bundle(output: Path, source_sha: str, config_path: Path = DEFAULT_CONFIG) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    output = output.resolve()
    if output == ROOT.resolve() or ROOT.resolve() in output.parents:
        raise ContractError("bundle output must be outside the source repository")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    copied: list[str] = []
    for relative in config["files"]:
        destination = output.joinpath(*PurePosixPath(relative).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file(relative), destination)
        copied.append(relative)
    provenance = {
        "schema": "szl.deployment-source/v4",
        "source": {
            "repository": config["source_repository"],
            "revision": source_sha,
            "ref": "refs/heads/main",
            "relation": "source-bound-static-release",
        },
        "target": {"repo_id": config["target"], "repo_type": "space", "sdk": "static"},
        "claims": {
            "source_file_digests": "MEASURED_IN_WORKFLOW",
            "live_hf_revision": "ATTESTED_AFTER_PUBLICATION",
            "runtime_quality": "NOT_INFERRED_FROM_DEPLOYMENT",
        },
    }
    (output / "SPACE_PROVENANCE.json").write_bytes(canonical_json(provenance))
    copied.append("SPACE_PROVENANCE.json")
    entries = _manifest_entries(output, copied)
    core = {
        "schema": "szl.hf-deploy-manifest/v3",
        "source_repository": config["source_repository"],
        "source_revision": source_sha,
        "target": config["target"],
        "files": entries,
        "file_count": len(entries),
        "self_manifest": {
            "path": "hf-deploy-manifest.json",
            "included_in_files": False,
            "reason": "self-digest is recursive; deployment result binds its exact HF blob",
        },
    }
    manifest = {**core, "bundle_sha256": sha256_bytes(canonical_json(core))}
    (output / "hf-deploy-manifest.json").write_bytes(canonical_json(manifest))
    return manifest


def validate_bundle(bundle: Path, source_sha: str, config_path: Path = DEFAULT_CONFIG) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    bundle = bundle.resolve()
    manifest_path = bundle / "hf-deploy-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ContractError("bundle manifest is missing or symbolic")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_keys = {
        "schema",
        "source_repository",
        "source_revision",
        "target",
        "files",
        "file_count",
        "self_manifest",
        "bundle_sha256",
    }
    if set(manifest) != expected_keys or manifest["schema"] != "szl.hf-deploy-manifest/v3":
        raise ContractError("bundle manifest does not match v3")
    if manifest["source_repository"] != config["source_repository"]:
        raise ContractError("bundle source repository mismatch")
    if manifest["source_revision"] != source_sha or manifest["target"] != config["target"]:
        raise ContractError("bundle source revision or target mismatch")
    entries = manifest["files"]
    if not isinstance(entries, list) or manifest["file_count"] != len(entries):
        raise ContractError("bundle file count mismatch")
    listed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "bytes",
            "git_blob_sha1",
            "sha256",
        }:
            raise ContractError("bundle manifest entry is malformed")
        relative = safe_relative(entry["path"])
        if relative in listed:
            raise ContractError("bundle manifest path is duplicated")
        listed.add(relative)
        path = bundle.joinpath(*PurePosixPath(relative).parts)
        if path.is_symlink() or not path.is_file():
            raise ContractError(f"bundle file is missing or symbolic: {relative}")
        data = path.read_bytes()
        if entry["bytes"] != len(data):
            raise ContractError(f"bundle byte count mismatch: {relative}")
        if entry["sha256"] != sha256_bytes(data) or entry["git_blob_sha1"] != git_blob_sha1(data):
            raise ContractError(f"bundle digest mismatch: {relative}")
    actual = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    if actual != listed | {"hf-deploy-manifest.json"}:
        raise ContractError("bundle tree is not closed by the manifest")
    core = {key: value for key, value in manifest.items() if key != "bundle_sha256"}
    if manifest["bundle_sha256"] != sha256_bytes(canonical_json(core)):
        raise ContractError("bundle aggregate digest mismatch")
    return manifest


def _request_json(url: str, token: str = "") -> object:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def require_governed_main(source_sha: str, config_path: Path = DEFAULT_CONFIG) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    source_ref = os.environ.get("GITHUB_REF", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    api_root = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if repository != config["source_repository"]:
        raise ContractError(f"unexpected GitHub repository: {repository!r}")
    if source_ref != "refs/heads/main":
        raise ContractError(f"refusing production release from {source_ref!r}")
    if not token:
        raise ContractError("GITHUB_TOKEN is required for protected-main reauthorization")
    metadata = _request_json(f"{api_root}/repos/{repository}", token)
    if not isinstance(metadata, dict) or metadata.get("default_branch") != "main":
        raise ContractError("repository default branch is not main")
    branch = _request_json(f"{api_root}/repos/{repository}/branches/main", token)
    live_sha = str(((branch or {}).get("commit") or {}).get("sha") or "").lower()
    if live_sha != source_sha:
        raise ContractError(
            f"refusing stale release: current main {live_sha!r} != source {source_sha!r}"
        )
    applicable_rules = _request_json(
        f"{api_root}/repos/{repository}/rules/branches/main", token
    )
    if not isinstance(applicable_rules, list):
        raise ContractError("active rules for main are unavailable")
    organization = repository.split("/", 1)[0]
    applicable_by_ruleset: dict[int, set[str]] = {}
    for rule in applicable_rules:
        if (
            not isinstance(rule, dict)
            or rule.get("ruleset_source_type") != "Organization"
            or rule.get("ruleset_source") != organization
        ):
            continue
        ruleset_id = rule.get("ruleset_id")
        rule_type = rule.get("type")
        if isinstance(ruleset_id, int) and isinstance(rule_type, str):
            applicable_by_ruleset.setdefault(ruleset_id, set()).add(rule_type)
    accepted: list[int] = []
    for ruleset_id, rule_types in applicable_by_ruleset.items():
        if not REQUIRED_RULE_TYPES <= rule_types:
            continue
        detail = _request_json(f"{api_root}/repos/{repository}/rulesets/{ruleset_id}", token)
        if (
            isinstance(detail, dict)
            and detail.get("enforcement") == "active"
            and detail.get("source_type") == "Organization"
            and detail.get("source") == organization
            and (detail or {}).get("bypass_actors") == []
            and detail.get("current_user_can_bypass") == "never"
        ):
            accepted.append(ruleset_id)
    if not accepted:
        raise ContractError(
            "default branch lacks an applicable inherited no-bypass PR, non-fast-forward, "
            "linear-history ruleset"
        )
    return {
        "status": "AUTHORIZED_EXACT_PROTECTED_MAIN",
        "source_revision": source_sha,
        "ruleset_ids": accepted,
    }


def deploy_bundle(
    bundle: Path,
    source_sha: str,
    result_path: Path,
    config_path: Path = DEFAULT_CONFIG,
) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    manifest = validate_bundle(bundle, source_sha, config_path)
    authorization = require_governed_main(source_sha, config_path)
    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise ContractError("HF_TOKEN is unavailable in the approved repository secret store")
    from huggingface_hub import HfApi

    api = HfApi(token=token)
    before = api.space_info(config["target"], token=token)
    before_sha = exact_sha(before.sha, "observed Hugging Face parent revision")
    commit = api.upload_folder(
        repo_id=config["target"],
        repo_type="space",
        folder_path=str(bundle),
        token=token,
        parent_commit=before_sha,
        delete_patterns="*",
        commit_message=f"Deploy GitHub source {source_sha}",
        commit_description=(
            f"Source: https://github.com/{config['source_repository']}/commit/{source_sha}\n"
            f"Bundle: {manifest['bundle_sha256']}"
        ),
    )
    target_sha = exact_sha(commit.oid, "published Hugging Face revision")
    result = {
        "schema": "szl.hf-deploy-result/v1",
        "status": "PUBLISHED_AWAITING_ATTESTATION",
        "source_revision": source_sha,
        "previous_hf_revision": before_sha,
        "hf_revision": target_sha,
        "bundle_sha256": manifest["bundle_sha256"],
        "target": config["target"],
        "authorization": authorization,
    }
    result_path.write_bytes(canonical_json(result))
    return result


def _hf_json(url: str) -> object:
    token = os.environ.get("HF_TOKEN", "")
    headers = {"Accept": "application/json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def _static_origin(target: str) -> str:
    owner, name = target.split("/", 1)
    owner = re.sub(r"[^a-z0-9-]+", "-", owner.lower()).strip("-")
    name = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return f"https://{owner}-{name}.hf.space"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _public_bytes(url: str) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def attest_bundle(
    bundle: Path,
    source_sha: str,
    result_path: Path,
    output_path: Path,
    timeout: int | None = None,
    config_path: Path = DEFAULT_CONFIG,
) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    manifest = validate_bundle(bundle, source_sha, config_path)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if result.get("source_revision") != source_sha or result.get("target") != config["target"]:
        raise ContractError("deployment result is not bound to this source and target")
    target_sha = exact_sha(result.get("hf_revision"), "deployment result revision")
    deadline = time.monotonic() + int(timeout or config["wait_running_seconds"])
    last_stage = last_sha = None
    while time.monotonic() < deadline:
        info = _hf_json(f"https://huggingface.co/api/spaces/{config['target']}")
        last_sha = (info or {}).get("sha")
        last_stage = ((info or {}).get("runtime") or {}).get("stage")
        if last_sha == target_sha and last_stage == "RUNNING":
            break
        if last_sha == target_sha and last_stage in TERMINAL_STAGES:
            raise ContractError(f"Space reached {last_stage} at {target_sha}")
        time.sleep(10)
    else:
        raise ContractError(
            f"Space did not reach exact RUNNING revision {target_sha}; "
            f"last stage={last_stage!r} sha={last_sha!r}"
        )
    tree_url = (
        f"https://huggingface.co/api/spaces/{config['target']}/tree/{target_sha}"
        "?recursive=true&expand=false"
    )
    tree = _hf_json(tree_url)
    if not isinstance(tree, list):
        raise ContractError("Hugging Face tree response is malformed")
    live = {
        row["path"]: row
        for row in tree
        if isinstance(row, dict) and row.get("type") == "file"
    }
    expected_paths = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    extras = set(live) - expected_paths
    if extras - set(config["allowed_hf_extras"]):
        raise ContractError(f"unmanaged files remain in live Space: {sorted(extras)}")
    if expected_paths - set(live):
        raise ContractError(f"live Space is missing files: {sorted(expected_paths - set(live))}")
    for relative in sorted(expected_paths):
        data = (bundle / relative).read_bytes()
        row = live[relative]
        if row.get("oid") != git_blob_sha1(data) or row.get("size") != len(data):
            raise ContractError(f"live Space bytes differ: {relative}")
    origin = _static_origin(config["target"])
    query = urllib.parse.urlencode({"source": source_sha})
    expected_ui = (bundle / "index.html").read_bytes()
    expected_provenance = (bundle / "SPACE_PROVENANCE.json").read_bytes()
    last_error = "not attempted"
    for attempt in range(12):
        status, body = _public_bytes(origin + "/?" + query)
        provenance_status, provenance_body = _public_bytes(
            origin + "/SPACE_PROVENANCE.json?" + query
        )
        try:
            provenance = json.loads(provenance_body)
        except json.JSONDecodeError:
            provenance = {}
        if (
            status == 200
            and body == expected_ui
            and provenance_status == 200
            and provenance_body == expected_provenance
            and ((provenance.get("source") or {}).get("revision") == source_sha)
        ):
            break
        last_error = (
            f"ui={status}/{len(body)} provenance={provenance_status}/"
            f"{(provenance.get('source') or {}).get('revision')!r}"
        )
        if attempt < 11:
            time.sleep(5)
    else:
        raise ContractError(f"public static source identity did not close: {last_error}")
    attestation = {
        "schema": "szl.hf-live-attestation/v1",
        "status": "MEASURED",
        "source_revision": source_sha,
        "hf_revision": target_sha,
        "runtime_stage": "RUNNING",
        "bundle_sha256": manifest["bundle_sha256"],
        "files_verified": len(expected_paths),
        "public_source_identity": True,
        "target": config["target"],
    }
    output_path.write_bytes(canonical_json(attestation))
    return attestation


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--source-sha", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--bundle", type=Path, required=True)
    validate.add_argument("--source-sha", required=True)
    guard = subparsers.add_parser("guard")
    guard.add_argument("--source-sha", required=True)
    deploy = subparsers.add_parser("deploy")
    deploy.add_argument("--bundle", type=Path, required=True)
    deploy.add_argument("--source-sha", required=True)
    deploy.add_argument("--result", type=Path, required=True)
    attest = subparsers.add_parser("attest")
    attest.add_argument("--bundle", type=Path, required=True)
    attest.add_argument("--source-sha", required=True)
    attest.add_argument("--result", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--timeout", type=int)
    args = parser.parse_args()
    if args.command == "build":
        value = build_bundle(args.output, args.source_sha, args.config)
    elif args.command == "validate":
        value = validate_bundle(args.bundle, args.source_sha, args.config)
    elif args.command == "guard":
        value = require_governed_main(args.source_sha, args.config)
    elif args.command == "deploy":
        value = deploy_bundle(args.bundle, args.source_sha, args.result, args.config)
    else:
        value = attest_bundle(
            args.bundle,
            args.source_sha,
            args.result,
            args.output,
            args.timeout,
            args.config,
        )
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL-CLOSED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
