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
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / ".hf-space.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_RULE_TYPES = {
    "pull_request",
    "non_fast_forward",
    "required_linear_history",
    "required_signatures",
    "required_status_checks",
}
GITHUB_ACTIONS_INTEGRATION_ID = 15368
GOVERNED_RULESET_ID = 20597034
GOVERNED_RULESET_NAME = "static-spaces-governed-default-branches"
GOVERNED_RULESET_SOURCE = "szl-holdings"
TARGET_REPOSITORY_IDS = {
    "szl-holdings/lambda-gate-holo": 1295931629,
    "szl-holdings/governed-norm-holo": 1295931607,
    "szl-holdings/energy-attest-holo": 1295929955,
    "szl-holdings/receipt-chain-live": 1295940016,
    "szl-holdings/szl-provctl-live": 1295941247,
}
REQUIRED_STATUS_CONTEXTS = {
    "DCO": GITHUB_ACTIONS_INTEGRATION_ID,
    "validate-static-space": GITHUB_ACTIONS_INTEGRATION_ID,
}
TERMINAL_STAGES = {"BUILD_ERROR", "CONFIG_ERROR", "RUNTIME_ERROR"}
TRANSIENT_HTTP_STATUSES = frozenset({429} | set(range(500, 600)))
UA = "szl-hf-static-space/1.0"
DCO_TRAILER = re.compile(r"^Signed-off-by:\s*(.+?)\s*<([^<>\s]+)>$", re.IGNORECASE)


class ContractError(RuntimeError):
    """The release request does not satisfy the governed publication contract."""


class TransientReadbackError(RuntimeError):
    """A retryable public or Hugging Face readback transport failure."""


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


def _git_output(arguments: list[str]) -> str:
    executable = os.environ.get("GIT_EXECUTABLE", "git")
    try:
        result = subprocess.run(
            [executable, *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError) as error:
        raise ContractError(
            f"git command failed closed: {' '.join(arguments[:2])}"
        ) from error
    return result.stdout


def _normalized_identity(name: str, email: str) -> tuple[str, str]:
    return " ".join(name.split()).casefold(), email.strip().casefold()


def _matching_dco_trailer(
    message: str,
    author_name: str,
    author_email: str,
    committer_name: str,
    committer_email: str,
) -> bool:
    lines = message.rstrip().splitlines()
    trailer_block: list[str] = []
    for line in reversed(lines):
        if not line.strip():
            if trailer_block:
                break
            continue
        trailer_block.append(line.strip())
    trailer_block.reverse()
    identities = {
        _normalized_identity(author_name, author_email),
        _normalized_identity(committer_name, committer_email),
    }
    for line in trailer_block:
        match = DCO_TRAILER.fullmatch(line)
        if match and _normalized_identity(match.group(1), match.group(2)) in identities:
            return True
    return False


def validate_dco_range(base_sha: str, head_sha: str) -> dict[str, object]:
    base_sha = exact_sha(base_sha, "DCO base revision")
    head_sha = exact_sha(head_sha, "DCO head revision")
    if base_sha == head_sha:
        raise ContractError("DCO range contains no commits")
    _git_output(["merge-base", "--is-ancestor", base_sha, head_sha])
    revisions = [
        exact_sha(row.strip(), "DCO commit revision")
        for row in _git_output(["rev-list", "--reverse", f"{base_sha}..{head_sha}"]).splitlines()
        if row.strip()
    ]
    if not revisions:
        raise ContractError("DCO range contains no commits")
    for revision in revisions:
        metadata = _git_output(
            [
                "show",
                "-s",
                "--format=%an%x00%ae%x00%cn%x00%ce%x00%B",
                revision,
            ]
        )
        fields = metadata.split("\0", 4)
        if len(fields) != 5:
            raise ContractError(f"DCO metadata is malformed for commit {revision}")
        if not _matching_dco_trailer(fields[4], *fields[:4]):
            raise ContractError(f"commit lacks a matching DCO trailer: {revision}")
    return {
        "status": "DCO_VALID",
        "base_revision": base_sha,
        "head_revision": head_sha,
        "commit_count": len(revisions),
        "commits": revisions,
    }


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
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except (OSError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(
            f"JSON request failed closed for {url}: {type(error).__name__}"
        ) from error


def _pull_request_parameters_are_exact(parameters: object) -> bool:
    if not isinstance(parameters, dict):
        return False
    approvals = parameters.get("required_approving_review_count")
    return (
        type(approvals) is int
        and approvals == 0
        and parameters.get("dismiss_stale_reviews_on_push") is True
        and parameters.get("require_code_owner_review") is False
        and parameters.get("require_last_push_approval") is False
        and parameters.get("required_review_thread_resolution") is True
        and parameters.get("required_reviewers") == []
        and parameters.get("allowed_merge_methods") == ["squash", "rebase"]
    )


def _status_check_parameters_are_exact(parameters: object) -> bool:
    if not isinstance(parameters, dict):
        return False
    if parameters.get("strict_required_status_checks_policy") is not True:
        return False
    if parameters.get("do_not_enforce_on_create") is not False:
        return False
    required_checks = parameters.get("required_status_checks")
    if not isinstance(required_checks, list) or len(required_checks) != len(
        REQUIRED_STATUS_CONTEXTS
    ):
        return False
    bound_contexts = {
        row.get("context"): row.get("integration_id")
        for row in required_checks
        if isinstance(row, dict)
        and set(row) == {"context", "integration_id"}
        and isinstance(row.get("context"), str)
        and type(row.get("integration_id")) is int
    }
    return bound_contexts == REQUIRED_STATUS_CONTEXTS


def _ruleset_authorizes_exact_default_branch(
    detail: object, repository_id: int
) -> bool:
    if not isinstance(detail, dict):
        return False
    if (
        detail.get("id") != GOVERNED_RULESET_ID
        or detail.get("name") != GOVERNED_RULESET_NAME
        or detail.get("source") != GOVERNED_RULESET_SOURCE
        or detail.get("source_type") != "Organization"
        or detail.get("target") != "branch"
        or detail.get("enforcement") != "active"
    ):
        return False
    if detail.get("bypass_actors") != []:
        return False
    conditions = detail.get("conditions")
    if not isinstance(conditions, dict) or set(conditions) != {
        "repository_id",
        "ref_name",
    }:
        return False
    ref_name = conditions.get("ref_name")
    repository_condition = conditions.get("repository_id")
    if not isinstance(ref_name, dict) or set(ref_name) != {"include", "exclude"}:
        return False
    if ref_name.get("include") != ["~DEFAULT_BRANCH"] or ref_name.get("exclude") != []:
        return False
    if not isinstance(repository_condition, dict) or set(repository_condition) != {
        "repository_ids"
    }:
        return False
    repository_ids = repository_condition.get("repository_ids")
    if (
        not isinstance(repository_ids, list)
        or len(repository_ids) != len(TARGET_REPOSITORY_IDS)
        or any(type(value) is not int for value in repository_ids)
        or set(repository_ids) != set(TARGET_REPOSITORY_IDS.values())
        or repository_id not in repository_ids
    ):
        return False
    rows = detail.get("rules")
    if not isinstance(rows, list):
        return False
    typed_rows = [
        row for row in rows if isinstance(row, dict) and isinstance(row.get("type"), str)
    ]
    rules = {row["type"]: row for row in typed_rows}
    if len(typed_rows) != len(rules) or set(rules) != REQUIRED_RULE_TYPES:
        return False
    return _pull_request_parameters_are_exact(
        rules["pull_request"].get("parameters")
    ) and _status_check_parameters_are_exact(
        rules["required_status_checks"].get("parameters")
    )


def _effective_rules_prove_inherited_governance(rows: object) -> bool:
    if not isinstance(rows, list):
        return False
    inherited: list[dict] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("ruleset_id") != GOVERNED_RULESET_ID:
            continue
        if (
            row.get("ruleset_source") != GOVERNED_RULESET_SOURCE
            or row.get("ruleset_source_type") != "Organization"
        ):
            return False
        inherited.append(row)
    typed_rows = [
        row
        for row in inherited
        if isinstance(row.get("type"), str) and row.get("type") in REQUIRED_RULE_TYPES
    ]
    rules = {row["type"]: row for row in typed_rows}
    if len(typed_rows) != len(rules) or set(rules) != REQUIRED_RULE_TYPES:
        return False
    return _pull_request_parameters_are_exact(
        rules["pull_request"].get("parameters")
    ) and _status_check_parameters_are_exact(
        rules["required_status_checks"].get("parameters")
    )


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
    expected_repository_id = TARGET_REPOSITORY_IDS.get(repository)
    if expected_repository_id is None:
        raise ContractError("repository is not one of the governed static Space targets")
    metadata = _request_json(f"{api_root}/repos/{repository}", token)
    if (
        not isinstance(metadata, dict)
        or metadata.get("id") != expected_repository_id
        or metadata.get("full_name") != repository
        or metadata.get("default_branch") != "main"
    ):
        raise ContractError("repository identity or default branch is not exact")
    default_branch = metadata["default_branch"]
    encoded_branch = urllib.parse.quote(default_branch, safe="")
    branch = _request_json(
        f"{api_root}/repos/{repository}/branches/{encoded_branch}", token
    )
    live_sha = str(((branch or {}).get("commit") or {}).get("sha") or "").lower()
    if live_sha != source_sha:
        raise ContractError(
            f"refusing stale release: current main {live_sha!r} != source {source_sha!r}"
        )
    summaries = _request_json(
        f"{api_root}/repos/{repository}/rulesets?includes_parents=true", token
    )
    if not isinstance(summaries, list):
        raise ContractError("repository ruleset inventory is unavailable")
    summary = next(
        (
            row
            for row in summaries
            if isinstance(row, dict) and row.get("id") == GOVERNED_RULESET_ID
        ),
        None,
    )
    if (
        not isinstance(summary, dict)
        or summary.get("name") != GOVERNED_RULESET_NAME
        or summary.get("source") != GOVERNED_RULESET_SOURCE
        or summary.get("source_type") != "Organization"
        or summary.get("enforcement") != "active"
        or summary.get("target") != "branch"
    ):
        raise ContractError("governed organization ruleset is not actively inherited")
    detail = _request_json(
        f"{api_root}/repos/{repository}/rulesets/{GOVERNED_RULESET_ID}", token
    )
    if not _ruleset_authorizes_exact_default_branch(detail, expected_repository_id):
        raise ContractError(
            f"organization ruleset {GOVERNED_RULESET_ID} does not match the exact "
            "five-repository no-bypass static Space policy"
        )
    effective = _request_json(
        f"{api_root}/repos/{repository}/rules/branches/{encoded_branch}", token
    )
    if not _effective_rules_prove_inherited_governance(effective):
        raise ContractError(
            f"organization ruleset {GOVERNED_RULESET_ID} is not fully effective on "
            f"{repository}@{default_branch}"
        )
    return {
        "status": "AUTHORIZED_EXACT_PROTECTED_MAIN",
        "source_revision": source_sha,
        "repository_id": expected_repository_id,
        "default_branch": default_branch,
        "ruleset_ids": [GOVERNED_RULESET_ID],
        "required_status_contexts": sorted(REQUIRED_STATUS_CONTEXTS),
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
    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise ContractError("HF_TOKEN is unavailable in the approved repository secret store")
    from huggingface_hub import HfApi

    api = HfApi(token=token)
    before = api.space_info(config["target"], token=token)
    before_sha = exact_sha(before.sha, "observed Hugging Face parent revision")
    authorization = require_governed_main(source_sha, config_path)
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


def _sanitized_diagnostic(error: BaseException) -> str:
    message = f"{type(error).__name__}: {error}"
    message = " ".join(message.replace("\x00", " ").split())
    message = re.sub(
        r"(?i)(authorization|token|secret|private[-_ ]?key)(\s*[:=]\s*)\S+",
        r"\1\2<redacted>",
        message,
    )
    return message[:500]


def _hf_json(url: str) -> object:
    token = os.environ.get("HF_TOKEN", "")
    headers = {"Accept": "application/json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code in TRANSIENT_HTTP_STATUSES:
            raise TransientReadbackError(
                f"Hugging Face API transient HTTP {error.code}"
            ) from error
        raise ContractError(f"Hugging Face API terminal HTTP {error.code}") from error
    except (TimeoutError, ConnectionResetError, urllib.error.URLError, OSError) as error:
        raise TransientReadbackError(
            f"Hugging Face API transient transport {type(error).__name__}"
        ) from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("Hugging Face API returned malformed JSON") from error


def _static_origin(target: str) -> str:
    owner, name = target.split("/", 1)
    owner = re.sub(r"[^a-z0-9-]+", "-", owner.lower()).strip("-")
    name = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return f"https://{owner}-{name}.static.hf.space"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _public_response(url: str) -> tuple[int, bytes, str | None]:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            return response.status, response.read(), response.headers.get("Location")
    except urllib.error.HTTPError as error:
        if error.code in TRANSIENT_HTTP_STATUSES:
            raise TransientReadbackError(
                f"public readback transient HTTP {error.code}"
            ) from error
        location = error.headers.get("Location") if error.headers is not None else None
        return error.code, error.read(), location
    except (TimeoutError, ConnectionResetError, urllib.error.URLError, OSError) as error:
        raise TransientReadbackError(
            f"public readback transient transport {type(error).__name__}"
        ) from error


def _fetch_public_index(origin: str, source_sha: str) -> bytes:
    source_sha = exact_sha(source_sha)
    query = urllib.parse.urlencode({"source": source_sha})
    root_url = origin + "/?" + query
    status, _, location = _public_response(root_url)
    if status != 302 or not location:
        raise ContractError(f"public static root expected one 302 redirect, observed {status}")
    redirected = urllib.parse.urljoin(root_url, location)
    expected_origin = urllib.parse.urlsplit(origin)
    actual = urllib.parse.urlsplit(redirected)
    if (
        actual.scheme.lower() != expected_origin.scheme.lower()
        or actual.netloc.lower() != expected_origin.netloc.lower()
        or actual.path != "/index.html"
        or actual.query != query
        or actual.fragment
    ):
        raise ContractError(f"public static root returned an unsafe redirect: {location!r}")
    index_status, body, second_location = _public_response(redirected)
    if index_status != 200 or second_location is not None:
        raise ContractError(
            f"public index expected terminal 200 without redirect, observed {index_status}"
        )
    return body


def require_exact_public_index(actual: bytes, expected: bytes) -> str:
    actual_digest = sha256_bytes(actual)
    expected_digest = sha256_bytes(expected)
    if actual != expected or actual_digest != expected_digest:
        raise ContractError(
            f"public index bytes differ: expected sha256={expected_digest} "
            f"observed sha256={actual_digest}"
        )
    return expected_digest


def verify_live_tree(bundle: Path, tree: object, allowed_extras: list[str]) -> int:
    if not isinstance(tree, list):
        raise ContractError("Hugging Face tree response is malformed")
    live = {
        row["path"]: row
        for row in tree
        if isinstance(row, dict) and row.get("type") == "file" and "path" in row
    }
    expected_paths = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    extras = set(live) - expected_paths
    if extras - set(allowed_extras):
        raise ContractError(f"unmanaged files remain in live Space: {sorted(extras)}")
    if expected_paths - set(live):
        raise ContractError(f"live Space is missing files: {sorted(expected_paths - set(live))}")
    for relative in sorted(expected_paths):
        data = (bundle / relative).read_bytes()
        row = live[relative]
        if row.get("oid") != git_blob_sha1(data) or row.get("size") != len(data):
            raise ContractError(f"live Space bytes differ: {relative}")
    return len(expected_paths)


def _retry_transient(action, deadline: float, label: str):
    last_diagnostic = "no response"
    while time.monotonic() < deadline:
        try:
            return action()
        except TransientReadbackError as error:
            last_diagnostic = _sanitized_diagnostic(error)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(5.0, remaining))
    raise ContractError(
        f"{label} exhausted the bounded readback deadline; last={last_diagnostic}"
    )


def _wait_for_exact_running(target: str, target_sha: str, deadline: float) -> tuple[str, str]:
    last_stage = last_sha = None
    url = f"https://huggingface.co/api/spaces/{target}"
    while time.monotonic() < deadline:
        info = _retry_transient(lambda: _hf_json(url), deadline, "Space runtime readback")
        if not isinstance(info, dict) or not isinstance(info.get("runtime"), dict):
            raise ContractError("Space runtime readback schema is malformed")
        last_sha = info.get("sha")
        last_stage = info["runtime"].get("stage")
        if not isinstance(last_sha, str) or not HEX40.fullmatch(last_sha.lower()):
            raise ContractError("Space runtime revision schema is malformed")
        last_sha = last_sha.lower()
        if not isinstance(last_stage, str) or not last_stage:
            raise ContractError("Space runtime stage schema is malformed")
        if last_sha == target_sha and last_stage == "RUNNING":
            return last_stage, last_sha
        if last_sha == target_sha and last_stage in TERMINAL_STAGES:
            raise ContractError(f"Space reached {last_stage} at {target_sha}")
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(10.0, remaining))
    raise ContractError(
        f"Space did not reach exact RUNNING revision {target_sha}; "
        f"last stage={last_stage!r} sha={last_sha!r}"
    )


def _read_exact_public_identity(
    origin: str,
    source_sha: str,
    expected_index: bytes,
    expected_provenance: bytes,
    deadline: float,
) -> str:
    query = urllib.parse.urlencode({"source": source_sha})

    def read_once() -> str:
        public_index = _fetch_public_index(origin, source_sha)
        public_index_sha256 = require_exact_public_index(public_index, expected_index)
        provenance_status, provenance_body, provenance_location = _public_response(
            origin + "/SPACE_PROVENANCE.json?" + query
        )
        if provenance_location is not None:
            raise ContractError("public provenance route unexpectedly redirected")
        if provenance_status != 200:
            raise ContractError(
                f"public provenance expected terminal 200, observed {provenance_status}"
            )
        if provenance_body != expected_provenance:
            raise ContractError(
                "public provenance bytes differ: "
                f"expected sha256={sha256_bytes(expected_provenance)} "
                f"observed sha256={sha256_bytes(provenance_body)}"
            )
        return public_index_sha256

    return _retry_transient(read_once, deadline, "public static source identity")


def _write_partial_evidence(
    path: Path,
    source_sha: str,
    target_sha: str,
    manifest: dict,
    target: str,
    failure_stage: str,
    error: BaseException,
    observations: dict[str, object],
) -> dict:
    evidence = {
        "schema": "szl.hf-publication-partial/v1",
        "status": "PARTIAL",
        "measured": False,
        "live_success": False,
        "source_revision": source_sha,
        "hf_revision": target_sha,
        "bundle_sha256": manifest["bundle_sha256"],
        "target": target,
        "failure_stage": failure_stage,
        "diagnostic": _sanitized_diagnostic(error),
        "observations": observations,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(evidence))
    return evidence


def attest_bundle(
    bundle: Path,
    source_sha: str,
    result_path: Path,
    output_path: Path,
    timeout: int | None = None,
    config_path: Path = DEFAULT_CONFIG,
    failure_output_path: Path | None = None,
) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    manifest = validate_bundle(bundle, source_sha, config_path)
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if (
        result.get("schema") != "szl.hf-deploy-result/v1"
        or result.get("status") != "PUBLISHED_AWAITING_ATTESTATION"
        or result.get("source_revision") != source_sha
        or result.get("target") != config["target"]
        or result.get("bundle_sha256") != manifest["bundle_sha256"]
    ):
        raise ContractError("deployment result is not bound to this source and target")
    target_sha = exact_sha(result.get("hf_revision"), "deployment result revision")
    deadline = time.monotonic() + int(timeout or config["wait_running_seconds"])
    failure_output_path = failure_output_path or output_path.with_name(
        "hf-publication-partial.json"
    )
    observations: dict[str, object] = {
        "runtime_stage": None,
        "runtime_revision": None,
        "files_verified": None,
        "public_source_identity": False,
    }
    failure_stage = "runtime_readback"
    try:
        runtime_stage, runtime_sha = _wait_for_exact_running(
            config["target"], target_sha, deadline
        )
        observations["runtime_stage"] = runtime_stage
        observations["runtime_revision"] = runtime_sha
        failure_stage = "tree_readback"
        tree_url = (
            f"https://huggingface.co/api/spaces/{config['target']}/tree/{target_sha}"
            "?recursive=true&expand=false"
        )
        tree = _retry_transient(
            lambda: _hf_json(tree_url), deadline, "Space tree readback"
        )
        files_verified = verify_live_tree(bundle, tree, config["allowed_hf_extras"])
        observations["files_verified"] = files_verified
        failure_stage = "public_readback"
        origin = _static_origin(config["target"])
        expected_index = (bundle / "index.html").read_bytes()
        expected_provenance = (bundle / "SPACE_PROVENANCE.json").read_bytes()
        public_index_sha256 = _read_exact_public_identity(
            origin, source_sha, expected_index, expected_provenance, deadline
        )
        observations["public_source_identity"] = True
        failure_stage = "post_readback_governance"
        final_authorization = require_governed_main(source_sha, config_path)
    except Exception as error:
        _write_partial_evidence(
            failure_output_path,
            source_sha,
            target_sha,
            manifest,
            config["target"],
            failure_stage,
            error,
            observations,
        )
        raise ContractError(
            f"post-publication verification failed closed at {failure_stage}; "
            "partial evidence was written"
        ) from error
    attestation = {
        "schema": "szl.hf-live-attestation/v1",
        "status": "MEASURED",
        "source_revision": source_sha,
        "hf_revision": target_sha,
        "runtime_stage": "RUNNING",
        "bundle_sha256": manifest["bundle_sha256"],
        "files_verified": files_verified,
        "public_source_identity": True,
        "public_index_bytes": len(expected_index),
        "public_index_sha256": public_index_sha256,
        "public_provenance_sha256": sha256_bytes(expected_provenance),
        "target": config["target"],
        "authorization": final_authorization,
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
    dco = subparsers.add_parser("dco")
    dco.add_argument("--base-sha", required=True)
    dco.add_argument("--head-sha", required=True)
    deploy = subparsers.add_parser("deploy")
    deploy.add_argument("--bundle", type=Path, required=True)
    deploy.add_argument("--source-sha", required=True)
    deploy.add_argument("--result", type=Path, required=True)
    attest = subparsers.add_parser("attest")
    attest.add_argument("--bundle", type=Path, required=True)
    attest.add_argument("--source-sha", required=True)
    attest.add_argument("--result", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--failure-output", type=Path, required=True)
    attest.add_argument("--timeout", type=int)
    args = parser.parse_args()
    if args.command == "build":
        value = build_bundle(args.output, args.source_sha, args.config)
    elif args.command == "validate":
        value = validate_bundle(args.bundle, args.source_sha, args.config)
    elif args.command == "guard":
        value = require_governed_main(args.source_sha, args.config)
    elif args.command == "dco":
        value = validate_dco_range(args.base_sha, args.head_sha)
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
            args.failure_output,
        )
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL-CLOSED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
