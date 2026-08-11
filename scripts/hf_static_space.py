#!/usr/bin/env python3
"""Build, publish, and attest an exact protected-main static Space bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
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
GITHUB_ACTIONS_INTEGRATION_ID = 15368
TARGET_REPOSITORY_IDS = {
    "szl-holdings/lambda-gate-holo": 1295931629,
    "szl-holdings/governed-norm-holo": 1295931607,
    "szl-holdings/energy-attest-holo": 1295929955,
    "szl-holdings/receipt-chain-live": 1295940016,
    "szl-holdings/szl-provctl-live": 1295941247,
}
TARGET_REQUIRED_WORKFLOW_IDS = {
    "szl-holdings/lambda-gate-holo": 330468835,
    "szl-holdings/governed-norm-holo": 330468861,
    "szl-holdings/energy-attest-holo": 330468877,
    "szl-holdings/receipt-chain-live": 330468896,
    "szl-holdings/szl-provctl-live": 330468912,
}
TARGET_RELEASE_WORKFLOW_IDS = {
    "szl-holdings/lambda-gate-holo": 330179530,
    "szl-holdings/governed-norm-holo": 330179524,
    "szl-holdings/energy-attest-holo": 330179529,
    "szl-holdings/receipt-chain-live": 330179521,
    "szl-holdings/szl-provctl-live": 330179528,
}
REQUIRED_STATUS_CONTEXTS = {
    "DCO": GITHUB_ACTIONS_INTEGRATION_ID,
    "validate-static-space": GITHUB_ACTIONS_INTEGRATION_ID,
}
REQUIRED_WORKFLOW_NAME = "External release boundary"
REQUIRED_WORKFLOW_PATH = ".github/workflows/release-boundary-required.yml"
RELEASE_WORKFLOW_NAME = "Governed static Space release"
RELEASE_WORKFLOW_PATH = ".github/workflows/hf-static-space.yml"
TERMINAL_STAGES = {"BUILD_ERROR", "CONFIG_ERROR", "RUNTIME_ERROR"}
TRANSIENT_HTTP_STATUSES = frozenset({429} | set(range(500, 600)))
HF_REQUEST_TIMEOUT_CAP = 45.0
PUBLIC_REQUEST_TIMEOUT_CAP = 30.0
DEPLOY_DEADLINE_SECONDS = 300.0
MUTATION_READBACK_SECONDS = 90.0
UA = "szl-hf-static-space/1.0"
GITHUB_API_VERSION = "2026-03-10"
GITHUB_PER_PAGE = 100
GITHUB_MAX_PAGES = 100
GOVERNED_MERGE_SCHEMA = "szl.github-governed-merge/v3"
PR_BODY_MARKER_SCHEMA = "szl.pr-head/v1"
PR_BODY_EVIDENCE_SCHEMA = "szl.pr-body-head/v1"
PR_BODY_MARKER_PREFIX = "<!-- szl-release-evidence:"
PR_BODY_MARKER_SUFFIX = " -->"
DCO_TRAILER = re.compile(r"^Signed-off-by:\s*(.+?)\s*<([^<>\s]+)>$", re.IGNORECASE)
SOURCE_RELATION = "source-bound-static-release"


class ContractError(RuntimeError):
    """The release request does not satisfy the governed publication contract."""


class TransientReadbackError(RuntimeError):
    """A retryable public or Hugging Face readback transport failure."""


class MutationDeadlineExpired(TimeoutError):
    """The strict wall-clock mutation deadline expired after call entry."""


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


def _source_identity(config: dict[str, object], source_sha: str) -> dict[str, str]:
    return {
        "repository": str(config["source_repository"]),
        "revision": exact_sha(source_sha),
        "relation": SOURCE_RELATION,
    }


def _remaining_timeout(deadline: float, cap: float, label: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractError(f"{label} refused because its wall-clock deadline expired")
    return min(float(cap), remaining)


def _require_strict_mutation_timer() -> None:
    if not all(
        hasattr(signal, attribute)
        for attribute in ("SIGALRM", "ITIMER_REAL", "setitimer")
    ):
        raise ContractError("strict mutation wall-clock enforcement is unavailable")


def _run_with_wall_clock_deadline(action, deadline: float, label: str):
    timeout = _remaining_timeout(deadline, DEPLOY_DEADLINE_SECONDS, label)
    _require_strict_mutation_timer()
    previous_handler = signal.getsignal(signal.SIGALRM)
    started = time.monotonic()

    def expire(_signum, _frame):  # noqa: ANN001
        raise MutationDeadlineExpired(f"{label} exceeded its wall-clock deadline")

    signal.signal(signal.SIGALRM, expire)
    previous_delay, previous_interval = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return action()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_delay > 0:
            elapsed = time.monotonic() - started
            signal.setitimer(
                signal.ITIMER_REAL,
                max(0.000001, previous_delay - elapsed),
                previous_interval,
            )


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
        "source": {**_source_identity(config, source_sha), "ref": "refs/heads/main"},
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
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": UA,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
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


def _paged_url(url: str, page: int) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True
        )
        if key not in {"page", "per_page"}
    ]
    query.extend((("per_page", str(GITHUB_PER_PAGE)), ("page", str(page))))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), "")
    )


def _complete_list_inventory(url: str, token: str, label: str) -> list[dict]:
    items: list[dict] = []
    observed_ids: set[int] = set()
    for page in range(1, GITHUB_MAX_PAGES + 1):
        rows = _request_json(_paged_url(url, page), token)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ContractError(f"{label} page is unavailable or malformed")
        if len(rows) > GITHUB_PER_PAGE:
            raise ContractError(f"{label} page exceeds the requested bound")
        for row in rows:
            item_id = row.get("id")
            if type(item_id) is not int or item_id <= 0 or item_id in observed_ids:
                raise ContractError(f"{label} identity is malformed or duplicated")
            observed_ids.add(item_id)
            items.append(row)
        if len(rows) < GITHUB_PER_PAGE:
            return sorted(items, key=lambda row: row["id"])
    raise ContractError(f"{label} exceeded the bounded pagination limit")


def _complete_object_inventory(
    url: str, token: str, key: str, label: str
) -> list[dict]:
    items: list[dict] = []
    observed_ids: set[int] = set()
    expected_total: int | None = None
    for page in range(1, GITHUB_MAX_PAGES + 1):
        response = _request_json(_paged_url(url, page), token)
        if not isinstance(response, dict) or not isinstance(response.get(key), list):
            raise ContractError(f"{label} inventory is unavailable")
        total = response.get("total_count")
        rows = response[key]
        if type(total) is not int or total < 0:
            raise ContractError(f"{label} total count is malformed")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise ContractError(f"{label} total count changed during pagination")
        if len(rows) > GITHUB_PER_PAGE or any(not isinstance(row, dict) for row in rows):
            raise ContractError(f"{label} page is incomplete or malformed")
        for row in rows:
            item_id = row.get("id")
            if type(item_id) is not int or item_id <= 0 or item_id in observed_ids:
                raise ContractError(f"{label} identity is malformed or duplicated")
            observed_ids.add(item_id)
            items.append(row)
        if len(items) > expected_total:
            raise ContractError(f"{label} inventory exceeds its total count")
        if len(items) == expected_total:
            return sorted(items, key=lambda row: row["id"])
        if len(rows) < GITHUB_PER_PAGE:
            raise ContractError(f"{label} inventory ended before its total count")
    raise ContractError(f"{label} exceeded the bounded pagination limit")


def exact_pr_body_evidence(body: object, repository: str, head_sha: str) -> dict:
    head_sha = exact_sha(head_sha, "pull-request body head revision")
    if not isinstance(body, str):
        raise ContractError("pull-request body is unavailable")
    marker_lines = [
        line for line in body.splitlines() if "szl-release-evidence:" in line
    ]
    if len(marker_lines) != 1:
        raise ContractError("pull-request body must contain one exact release marker")
    marker = marker_lines[0]
    if not marker.startswith(PR_BODY_MARKER_PREFIX) or not marker.endswith(
        PR_BODY_MARKER_SUFFIX
    ):
        raise ContractError("pull-request release marker is malformed")
    payload_text = marker[
        len(PR_BODY_MARKER_PREFIX) : -len(PR_BODY_MARKER_SUFFIX)
    ]
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as error:
        raise ContractError("pull-request release marker JSON is malformed") from error
    expected = {
        "head_revision": head_sha,
        "repository": repository,
        "schema": PR_BODY_MARKER_SCHEMA,
    }
    canonical_payload = json.dumps(
        expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    if payload != expected or marker != (
        PR_BODY_MARKER_PREFIX + canonical_payload + PR_BODY_MARKER_SUFFIX
    ):
        raise ContractError("pull-request release marker is not exact and canonical")
    return {
        "schema": PR_BODY_EVIDENCE_SCHEMA,
        "repository": repository,
        "head_revision": head_sha,
        "body_sha256": sha256_bytes(body.encode("utf-8")),
    }


def validate_pr_body_event(
    source_sha: str, event_path: Path, config_path: Path = DEFAULT_CONFIG
) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    repository = config["source_repository"]
    repository_id = TARGET_REPOSITORY_IDS[repository]
    event = _load_event(event_path)
    event_repository = event.get("repository")
    pull = event.get("pull_request")
    head = pull.get("head") if isinstance(pull, dict) else None
    head_repository = head.get("repo") if isinstance(head, dict) else None
    if (
        not isinstance(event_repository, dict)
        or event_repository.get("id") != repository_id
        or event_repository.get("full_name") != repository
        or not isinstance(pull, dict)
        or not isinstance(head, dict)
        or head.get("sha") != source_sha
        or not isinstance(head_repository, dict)
        or head_repository.get("id") != repository_id
        or head_repository.get("full_name") != repository
    ):
        raise ContractError("pull-request event is not bound to this exact head")
    return exact_pr_body_evidence(pull.get("body"), repository, source_sha)


def _load_event(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("GitHub push event is unreadable") from error
    if not isinstance(value, dict):
        raise ContractError("GitHub push event is not an object")
    return value


def _check_run_id_from_url(value: object, api_root: str, repository: str) -> int:
    prefix = f"{api_root}/repos/{repository}/check-runs/"
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ContractError("workflow job check-run URL is not exact")
    suffix = value[len(prefix) :]
    if not suffix.isdigit() or int(suffix) <= 0 or "/" in suffix:
        raise ContractError("workflow job check-run identity is malformed")
    return int(suffix)


def _run_pull_is_exact(
    pull_requests: object,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
) -> bool:
    if not isinstance(pull_requests, list) or len(pull_requests) != 1:
        return False
    pull = pull_requests[0]
    head = pull.get("head") if isinstance(pull, dict) else None
    base = pull.get("base") if isinstance(pull, dict) else None
    return (
        isinstance(pull, dict)
        and pull.get("number") == pull_number
        and isinstance(head, dict)
        and head.get("ref") == head_ref
        and head.get("sha") == head_sha
        and isinstance(head.get("repo"), dict)
        and head["repo"].get("id") == repository_id
        and isinstance(base, dict)
        and base.get("ref") == "main"
        and base.get("sha") == base_sha
        and isinstance(base.get("repo"), dict)
        and base["repo"].get("id") == repository_id
    )


def _run_is_exact(
    row: object,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
) -> bool:
    return (
        isinstance(row, dict)
        and row.get("workflow_id") == workflow_id
        and row.get("name") == workflow_name
        and row.get("path") == workflow_path
        and row.get("event") == "pull_request"
        and row.get("head_sha") == head_sha
        and isinstance(row.get("repository"), dict)
        and row["repository"].get("full_name") == repository
        and row["repository"].get("id") == repository_id
        and _run_pull_is_exact(
            row.get("pull_requests"),
            repository_id,
            pull_number,
            base_sha,
            head_ref,
            head_sha,
        )
    )


def _select_exact_pull_request_workflow(
    rows: list[dict],
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
    *,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
    label: str,
) -> dict:
    matches = [
        row
        for row in rows
        if _run_is_exact(
            row,
            repository,
            repository_id,
            pull_number,
            base_sha,
            head_ref,
            head_sha,
            workflow_id,
            workflow_name,
            workflow_path,
        )
    ]
    if not matches:
        raise ContractError(f"exact {label} did not run for this head")
    if any(
        type(row.get("id")) is not int
        or row["id"] <= 0
        or type(row.get("run_attempt")) is not int
        or row["run_attempt"] <= 0
        or type(row.get("check_suite_id")) is not int
        or row["check_suite_id"] <= 0
        for row in matches
    ):
        raise ContractError(f"exact {label} identity is malformed")
    selected = max(matches, key=lambda row: (row["id"], row["run_attempt"]))
    if (
        selected.get("status") != "completed"
        or selected.get("conclusion") != "success"
    ):
        raise ContractError(f"latest exact {label} did not succeed")
    return selected


def _bind_workflow_attempt(
    selected: dict,
    api_root: str,
    token: str,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
    *,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
    label: str,
    required_job_names: frozenset[str],
) -> tuple[dict[str, object], list[dict]]:
    run_id = selected["id"]
    run_attempt = selected["run_attempt"]
    check_suite_id = selected["check_suite_id"]
    run_url = f"{api_root}/repos/{repository}/actions/runs/{run_id}"
    attempt = _request_json(f"{run_url}/attempts/{run_attempt}", token)
    if (
        not _run_is_exact(
            attempt,
            repository,
            repository_id,
            pull_number,
            base_sha,
            head_ref,
            head_sha,
            workflow_id,
            workflow_name,
            workflow_path,
        )
        or attempt.get("id") != run_id
        or attempt.get("run_attempt") != run_attempt
        or attempt.get("check_suite_id") != check_suite_id
        or attempt.get("status") != "completed"
        or attempt.get("conclusion") != "success"
    ):
        raise ContractError(f"exact {label} attempt readback is not exact")
    jobs = _complete_object_inventory(
        f"{run_url}/attempts/{run_attempt}/jobs",
        token,
        "jobs",
        f"exact {label} attempt job",
    )
    if not jobs:
        raise ContractError(f"exact {label} attempt has no jobs")
    checks = _complete_object_inventory(
        f"{api_root}/repos/{repository}/check-suites/{check_suite_id}/check-runs?filter=all",
        token,
        "check_runs",
        f"exact {label} check-suite check-run",
    )
    checks_by_id = {row["id"]: row for row in checks}
    job_evidence: list[dict] = []
    for job in jobs:
        job_id = job.get("id")
        job_name = job.get("name")
        check_run_id = _check_run_id_from_url(
            job.get("check_run_url"), api_root, repository
        )
        check = checks_by_id.get(check_run_id)
        if (
            type(job_id) is not int
            or job_id <= 0
            or not isinstance(job_name, str)
            or not job_name
            or job.get("run_id") != run_id
            or job.get("run_url") != run_url
            or job.get("head_sha") != head_sha
            or job.get("workflow_name") != workflow_name
            or job.get("status") != "completed"
            or job.get("conclusion") not in {"success", "skipped"}
            or not isinstance(job.get("html_url"), str)
            or not isinstance(check, dict)
            or check.get("id") != check_run_id
            or check.get("url") != job.get("check_run_url")
            or check.get("name") != job_name
            or check.get("head_sha") != head_sha
            or check.get("status") != job.get("status")
            or check.get("conclusion") != job.get("conclusion")
            or check.get("details_url") != job.get("html_url")
            or not isinstance(check.get("check_suite"), dict)
            or check["check_suite"].get("id") != check_suite_id
            or not isinstance(check.get("app"), dict)
            or check["app"].get("id") != GITHUB_ACTIONS_INTEGRATION_ID
        ):
            raise ContractError(f"exact {label} job/check binding is not exact")
        job_evidence.append(
            {
                "app_id": GITHUB_ACTIONS_INTEGRATION_ID,
                "check_run_id": check_run_id,
                "check_suite_id": check_suite_id,
                "conclusion": job["conclusion"],
                "head_revision": head_sha,
                "job_id": job_id,
                "name": job_name,
                "run_attempt": run_attempt,
                "run_id": run_id,
                "status": "completed",
            }
        )
    if not any(row["conclusion"] == "success" for row in job_evidence):
        raise ContractError(f"exact {label} attempt has no successful job")
    required: list[dict] = []
    for name in sorted(required_job_names):
        matches = [row for row in job_evidence if row["name"] == name]
        if len(matches) != 1 or matches[0]["conclusion"] != "success":
            raise ContractError(f"required exact {label} job did not succeed: {name}")
        required.append(matches[0])
    workflow_evidence = {
        "base_revision": base_sha,
        "check_suite_id": check_suite_id,
        "conclusion": "success",
        "event": "pull_request",
        "head_ref": head_ref,
        "head_revision": head_sha,
        "jobs": sorted(job_evidence, key=lambda row: (row["name"], row["job_id"])),
        "name": workflow_name,
        "path": workflow_path,
        "pull_request_number": pull_number,
        "repository_id": repository_id,
        "run_attempt": run_attempt,
        "run_id": run_id,
        "status": "completed",
        "workflow_id": workflow_id,
    }
    return workflow_evidence, required


def _require_exact_pull_request_workflow(
    rows: list[dict],
    api_root: str,
    token: str,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
    *,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
    label: str,
    required_job_names: frozenset[str],
) -> tuple[dict[str, object], list[dict]]:
    selected = _select_exact_pull_request_workflow(
        rows,
        repository,
        repository_id,
        pull_number,
        base_sha,
        head_ref,
        head_sha,
        workflow_id=workflow_id,
        workflow_name=workflow_name,
        workflow_path=workflow_path,
        label=label,
    )
    return _bind_workflow_attempt(
        selected,
        api_root,
        token,
        repository,
        repository_id,
        pull_number,
        base_sha,
        head_ref,
        head_sha,
        workflow_id=workflow_id,
        workflow_name=workflow_name,
        workflow_path=workflow_path,
        label=label,
        required_job_names=required_job_names,
    )


def _require_release_workflow(
    rows: list[dict],
    api_root: str,
    token: str,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
) -> tuple[dict[str, object], list[dict]]:
    return _require_exact_pull_request_workflow(
        rows,
        api_root,
        token,
        repository,
        repository_id,
        pull_number,
        base_sha,
        head_ref,
        head_sha,
        workflow_id=TARGET_RELEASE_WORKFLOW_IDS[repository],
        workflow_name=RELEASE_WORKFLOW_NAME,
        workflow_path=RELEASE_WORKFLOW_PATH,
        label="publisher workflow",
        required_job_names=frozenset(REQUIRED_STATUS_CONTEXTS),
    )


def _require_boundary_workflow(
    rows: list[dict],
    api_root: str,
    token: str,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
) -> tuple[dict[str, object], list[dict]]:
    return _require_exact_pull_request_workflow(
        rows,
        api_root,
        token,
        repository,
        repository_id,
        pull_number,
        base_sha,
        head_ref,
        head_sha,
        workflow_id=TARGET_REQUIRED_WORKFLOW_IDS[repository],
        workflow_name=REQUIRED_WORKFLOW_NAME,
        workflow_path=REQUIRED_WORKFLOW_PATH,
        label="required release-boundary workflow",
        required_job_names=frozenset(),
    )


def _exact_merged_pull_projection(
    pull: object,
    candidate: dict,
    repository: str,
    repository_id: int,
    before_sha: str,
    source_sha: str,
) -> dict:
    if not isinstance(pull, dict) or pull.get("id") != candidate.get("id"):
        raise ContractError("merged pull-request readback is not exact")
    head = pull.get("head")
    base = pull.get("base")
    merged_by = pull.get("merged_by")
    head_sha = exact_sha((head or {}).get("sha"), "pull-request head revision")
    head_ref = (head or {}).get("ref")
    if (
        pull.get("number") != candidate.get("number")
        or pull.get("state") != "closed"
        or not pull.get("merged")
        or not isinstance(pull.get("merged_at"), str)
        or not pull["merged_at"]
        or pull.get("merge_commit_sha") != source_sha
        or not isinstance(base, dict)
        or base.get("ref") != "main"
        or base.get("sha") != before_sha
        or not isinstance(base.get("repo"), dict)
        or base["repo"].get("full_name") != repository
        or base["repo"].get("id") != repository_id
        or not isinstance(head, dict)
        or not isinstance(head_ref, str)
        or not head_ref
        or not isinstance(head.get("repo"), dict)
        or head["repo"].get("full_name") != repository
        or head["repo"].get("id") != repository_id
        or not isinstance(merged_by, dict)
        or not isinstance(merged_by.get("login"), str)
        or not merged_by["login"]
    ):
        raise ContractError("merged pull-request tuple is not exact")
    return {
        "base_revision": before_sha,
        "body_evidence": exact_pr_body_evidence(
            pull.get("body"), repository, head_sha
        ),
        "head_ref": head_ref,
        "head_revision": head_sha,
        "id": pull["id"],
        "merge_revision": source_sha,
        "merged_at": pull["merged_at"],
        "merged_by": merged_by["login"],
        "number": pull["number"],
    }


def _require_latest_run_still_exact(
    api_root: str,
    token: str,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
    evidence: dict,
) -> None:
    current = _request_json(
        f"{api_root}/repos/{repository}/actions/runs/{evidence['run_id']}", token
    )
    if (
        not _run_is_exact(
            current,
            repository,
            repository_id,
            pull_number,
            base_sha,
            head_ref,
            head_sha,
            evidence["workflow_id"],
            evidence["name"],
            evidence["path"],
        )
        or current.get("id") != evidence["run_id"]
        or current.get("run_attempt") != evidence["run_attempt"]
        or current.get("check_suite_id") != evidence["check_suite_id"]
        or current.get("status") != "completed"
        or current.get("conclusion") != "success"
    ):
        raise ContractError("workflow run advanced after exact-attempt authorization")


def require_governed_main(
    source_sha: str,
    event_path: Path,
    output_path: Path,
    config_path: Path = DEFAULT_CONFIG,
    *,
    failure_output_path: Path | None = None,
) -> dict:
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
    try:
        event = _load_event(event_path)
        before_sha = exact_sha(event.get("before"), "push before revision")
        after_sha = exact_sha(event.get("after"), "push after revision")
        event_repository = event.get("repository")
        if (
            event.get("ref") != "refs/heads/main"
            or after_sha != source_sha
            or not isinstance(event_repository, dict)
            or event_repository.get("id") != expected_repository_id
            or event_repository.get("full_name") != repository
            or event_repository.get("default_branch") != "main"
        ):
            raise ContractError("push event is not bound to this exact default branch")
        metadata = _request_json(f"{api_root}/repos/{repository}", token)
        if (
            not isinstance(metadata, dict)
            or metadata.get("id") != expected_repository_id
            or metadata.get("full_name") != repository
            or metadata.get("default_branch") != "main"
        ):
            raise ContractError("repository identity or default branch is not exact")
        branch = _request_json(f"{api_root}/repos/{repository}/branches/main", token)
        live_sha = str(((branch or {}).get("commit") or {}).get("sha") or "").lower()
        if live_sha != source_sha:
            raise ContractError(
                f"refusing stale release: current main {live_sha!r} != source {source_sha!r}"
            )
        associated_url = (
            f"{api_root}/repos/{repository}/commits/{source_sha}/pulls"
        )
        associated = _complete_list_inventory(
            associated_url, token, "associated pull-request"
        )
        candidates = [
            row
            for row in associated
            if isinstance(row, dict)
            and row.get("state") == "closed"
            and row.get("merged_at")
            and row.get("merge_commit_sha") == source_sha
            and isinstance(row.get("base"), dict)
            and row["base"].get("ref") == "main"
            and row["base"].get("sha") == before_sha
            and isinstance(row["base"].get("repo"), dict)
            and row["base"]["repo"].get("full_name") == repository
        ]
        if len(candidates) != 1:
            raise ContractError("exact main revision is not one unambiguous merged PR")
        candidate = candidates[0]
        number = candidate.get("number")
        if type(number) is not int or number <= 0:
            raise ContractError("associated pull-request number is malformed")
        pull = _request_json(f"{api_root}/repos/{repository}/pulls/{number}", token)
        pull_evidence = _exact_merged_pull_projection(
            pull,
            candidate,
            repository,
            expected_repository_id,
            before_sha,
            source_sha,
        )
        head_sha = pull_evidence["head_revision"]
        head_ref = pull_evidence["head_ref"]
        query = urllib.parse.urlencode(
            {"event": "pull_request", "head_sha": head_sha}
        )
        workflow_runs_url = f"{api_root}/repos/{repository}/actions/runs?{query}"
        workflow_runs = _complete_object_inventory(
            workflow_runs_url, token, "workflow_runs", "exact-head workflow-run"
        )
        release_workflow, checks = _require_release_workflow(
            workflow_runs,
            api_root,
            token,
            repository,
            expected_repository_id,
            number,
            before_sha,
            head_ref,
            head_sha,
        )
        boundary, _ = _require_boundary_workflow(
            workflow_runs,
            api_root,
            token,
            repository,
            expected_repository_id,
            number,
            before_sha,
            head_ref,
            head_sha,
        )
        final_workflow_runs = _complete_object_inventory(
            workflow_runs_url, token, "workflow_runs", "final exact-head workflow-run"
        )
        for workflow, workflow_id, workflow_name, workflow_path, label in (
            (
                release_workflow,
                TARGET_RELEASE_WORKFLOW_IDS[repository],
                RELEASE_WORKFLOW_NAME,
                RELEASE_WORKFLOW_PATH,
                "publisher workflow",
            ),
            (
                boundary,
                TARGET_REQUIRED_WORKFLOW_IDS[repository],
                REQUIRED_WORKFLOW_NAME,
                REQUIRED_WORKFLOW_PATH,
                "required release-boundary workflow",
            ),
        ):
            selected = _select_exact_pull_request_workflow(
                final_workflow_runs,
                repository,
                expected_repository_id,
                number,
                before_sha,
                head_ref,
                head_sha,
                workflow_id=workflow_id,
                workflow_name=workflow_name,
                workflow_path=workflow_path,
                label=label,
            )
            if (
                selected.get("id") != workflow["run_id"]
                or selected.get("run_attempt") != workflow["run_attempt"]
                or selected.get("check_suite_id") != workflow["check_suite_id"]
            ):
                raise ContractError(f"exact {label} advanced during authorization")
            _require_latest_run_still_exact(
                api_root,
                token,
                repository,
                expected_repository_id,
                number,
                before_sha,
                head_ref,
                head_sha,
                workflow,
            )
        final_pull = _request_json(
            f"{api_root}/repos/{repository}/pulls/{number}", token
        )
        final_pull_evidence = _exact_merged_pull_projection(
            final_pull,
            candidate,
            repository,
            expected_repository_id,
            before_sha,
            source_sha,
        )
        if canonical_json(final_pull_evidence) != canonical_json(pull_evidence):
            raise ContractError("merged pull-request evidence changed during authorization")
        final_associated = _complete_list_inventory(
            associated_url, token, "final associated pull-request"
        )
        if canonical_json(final_associated) != canonical_json(associated):
            raise ContractError(
                "associated pull-request inventory changed during authorization"
            )
        final_branch = _request_json(
            f"{api_root}/repos/{repository}/branches/main", token
        )
        final_main_sha = str(
            ((final_branch or {}).get("commit") or {}).get("sha") or ""
        ).lower()
        if final_main_sha != source_sha:
            raise ContractError("protected main changed during authorization")
        evidence = {
            "schema": GOVERNED_MERGE_SCHEMA,
            "status": "AUTHORIZED_EXACT_GOVERNED_MERGE",
            "source_revision": source_sha,
            "repository": {
                "default_branch": "main",
                "full_name": repository,
                "id": expected_repository_id,
            },
            "push": {"before": before_sha, "after": source_sha},
            "pull_request": pull_evidence,
            "required_checks": checks,
            "release_workflow": release_workflow,
            "required_workflow": boundary,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(canonical_json(evidence))
        if failure_output_path:
            failure_output_path.unlink(missing_ok=True)
        return evidence
    except Exception as error:
        if failure_output_path:
            failure = {
                "schema": "szl.github-governed-merge-failure/v1",
                "status": "GOVERNANCE_AUTHORIZATION_FAILED",
                "failure_stage": "governance_authorization",
                "source_revision": source_sha,
                "repository": repository,
                "receipt_minted": False,
                "deployment_success": False,
                "diagnostic": _sanitized_diagnostic(error),
            }
            failure_output_path.parent.mkdir(parents=True, exist_ok=True)
            failure_output_path.write_bytes(canonical_json(failure))
        raise


def _job_evidence_is_exact(
    job: object,
    run_id: int,
    run_attempt: int,
    check_suite_id: int,
    head_sha: str,
) -> bool:
    return (
        isinstance(job, dict)
        and set(job)
        == {
            "app_id",
            "check_run_id",
            "check_suite_id",
            "conclusion",
            "head_revision",
            "job_id",
            "name",
            "run_attempt",
            "run_id",
            "status",
        }
        and job.get("app_id") == GITHUB_ACTIONS_INTEGRATION_ID
        and type(job.get("check_run_id")) is int
        and job["check_run_id"] > 0
        and job.get("check_suite_id") == check_suite_id
        and job.get("conclusion") in {"success", "skipped"}
        and job.get("head_revision") == head_sha
        and type(job.get("job_id")) is int
        and job["job_id"] > 0
        and isinstance(job.get("name"), str)
        and bool(job["name"])
        and job.get("run_attempt") == run_attempt
        and job.get("run_id") == run_id
        and job.get("status") == "completed"
    )


def _workflow_evidence_is_exact(
    workflow: object,
    *,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
    required_job_names: frozenset[str],
) -> bool:
    if not isinstance(workflow, dict) or set(workflow) != {
        "base_revision",
        "check_suite_id",
        "conclusion",
        "event",
        "head_ref",
        "head_revision",
        "jobs",
        "name",
        "path",
        "pull_request_number",
        "repository_id",
        "run_attempt",
        "run_id",
        "status",
        "workflow_id",
    }:
        return False
    run_id = workflow.get("run_id")
    run_attempt = workflow.get("run_attempt")
    check_suite_id = workflow.get("check_suite_id")
    jobs = workflow.get("jobs")
    if (
        workflow.get("workflow_id") != workflow_id
        or workflow.get("name") != workflow_name
        or workflow.get("path") != workflow_path
        or workflow.get("event") != "pull_request"
        or workflow.get("repository_id") != repository_id
        or workflow.get("pull_request_number") != pull_number
        or workflow.get("base_revision") != base_sha
        or workflow.get("head_ref") != head_ref
        or workflow.get("head_revision") != head_sha
        or workflow.get("status") != "completed"
        or workflow.get("conclusion") != "success"
        or type(run_id) is not int
        or run_id <= 0
        or type(run_attempt) is not int
        or run_attempt <= 0
        or type(check_suite_id) is not int
        or check_suite_id <= 0
        or not isinstance(jobs, list)
        or not jobs
        or not all(
            _job_evidence_is_exact(
                job, run_id, run_attempt, check_suite_id, head_sha
            )
            for job in jobs
        )
    ):
        return False
    if len({job["job_id"] for job in jobs}) != len(jobs) or len(
        {job["check_run_id"] for job in jobs}
    ) != len(jobs):
        return False
    if not any(job["conclusion"] == "success" for job in jobs):
        return False
    return all(
        len([job for job in jobs if job["name"] == name]) == 1
        and next(job for job in jobs if job["name"] == name)["conclusion"]
        == "success"
        for name in required_job_names
    )


def load_governed_merge(
    path: Path, source_sha: str, config_path: Path = DEFAULT_CONFIG
) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    try:
        raw = path.read_bytes()
        evidence = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("governed-merge evidence is unreadable") from error
    if not isinstance(evidence, dict) or raw != canonical_json(evidence):
        raise ContractError("governed-merge evidence is not canonical")
    expected_repository = config["source_repository"]
    repository = evidence.get("repository")
    push = evidence.get("push")
    pull = evidence.get("pull_request")
    checks = evidence.get("required_checks")
    release_workflow = evidence.get("release_workflow")
    boundary_workflow = evidence.get("required_workflow")
    if (
        set(evidence)
        != {
            "schema",
            "status",
            "source_revision",
            "repository",
            "push",
            "pull_request",
            "required_checks",
            "release_workflow",
            "required_workflow",
        }
        or evidence.get("schema") != GOVERNED_MERGE_SCHEMA
        or evidence.get("status") != "AUTHORIZED_EXACT_GOVERNED_MERGE"
        or evidence.get("source_revision") != source_sha
        or not isinstance(repository, dict)
        or set(repository) != {"default_branch", "full_name", "id"}
        or repository.get("full_name") != expected_repository
        or repository.get("id") != TARGET_REPOSITORY_IDS[expected_repository]
        or repository.get("default_branch") != "main"
        or not isinstance(push, dict)
        or set(push) != {"before", "after"}
        or push.get("after") != source_sha
        or not isinstance(push.get("before"), str)
        or not HEX40.fullmatch(push["before"])
    ):
        raise ContractError("governed-merge evidence is not bound to this release")
    if not isinstance(pull, dict) or set(pull) != {
        "base_revision",
        "body_evidence",
        "head_ref",
        "head_revision",
        "id",
        "merge_revision",
        "merged_at",
        "merged_by",
        "number",
    }:
        raise ContractError("governed-merge pull-request evidence is malformed")
    body_evidence = pull.get("body_evidence")
    if (
        pull.get("base_revision") != push.get("before")
        or not isinstance(pull.get("head_ref"), str)
        or not pull["head_ref"]
        or not isinstance(pull.get("head_revision"), str)
        or not HEX40.fullmatch(pull["head_revision"])
        or type(pull.get("id")) is not int
        or pull["id"] <= 0
        or pull.get("merge_revision") != source_sha
        or not isinstance(pull.get("merged_at"), str)
        or not pull["merged_at"]
        or not isinstance(pull.get("merged_by"), str)
        or not pull["merged_by"]
        or type(pull.get("number")) is not int
        or pull["number"] <= 0
        or not isinstance(body_evidence, dict)
        or set(body_evidence)
        != {"body_sha256", "head_revision", "repository", "schema"}
        or body_evidence.get("schema") != PR_BODY_EVIDENCE_SCHEMA
        or body_evidence.get("repository") != expected_repository
        or body_evidence.get("head_revision") != pull.get("head_revision")
        or not isinstance(body_evidence.get("body_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", body_evidence["body_sha256"]) is None
    ):
        raise ContractError("governed-merge pull-request evidence is not exact")
    common = {
        "repository_id": repository["id"],
        "pull_number": pull["number"],
        "base_sha": pull["base_revision"],
        "head_ref": pull["head_ref"],
        "head_sha": pull["head_revision"],
    }
    if not _workflow_evidence_is_exact(
        release_workflow,
        workflow_id=TARGET_RELEASE_WORKFLOW_IDS[expected_repository],
        workflow_name=RELEASE_WORKFLOW_NAME,
        workflow_path=RELEASE_WORKFLOW_PATH,
        required_job_names=frozenset(REQUIRED_STATUS_CONTEXTS),
        **common,
    ) or not _workflow_evidence_is_exact(
        boundary_workflow,
        workflow_id=TARGET_REQUIRED_WORKFLOW_IDS[expected_repository],
        workflow_name=REQUIRED_WORKFLOW_NAME,
        workflow_path=REQUIRED_WORKFLOW_PATH,
        required_job_names=frozenset(),
        **common,
    ):
        raise ContractError("governed-merge workflow evidence is not exact")
    expected_checks = sorted(
        [
            job
            for job in release_workflow["jobs"]
            if job["name"] in REQUIRED_STATUS_CONTEXTS
        ],
        key=lambda row: row["name"],
    )
    if checks != expected_checks:
        raise ContractError("governed-merge required-check evidence is not exact")
    return evidence


def _recover_authoritative_revision(
    bundle: Path,
    target: str,
    previous_sha: str,
    allowed_extras: list[str],
    deadline: float,
) -> str:
    info_url = f"https://huggingface.co/api/spaces/{target}"
    info = _retry_transient(
        lambda: _hf_json(info_url, deadline),
        deadline,
        "ambiguous mutation revision readback",
    )
    if not isinstance(info, dict):
        raise ContractError("ambiguous mutation revision readback schema is malformed")
    candidate = exact_sha(info.get("sha"), "authoritative Hugging Face revision")
    if candidate == previous_sha:
        raise ContractError("authoritative readback still reports the pre-upload revision")
    tree_url = (
        f"https://huggingface.co/api/spaces/{target}/tree/{candidate}"
        "?recursive=true&expand=false"
    )
    tree = _retry_transient(
        lambda: _hf_json(tree_url, deadline),
        deadline,
        "ambiguous mutation exact-tree readback",
    )
    verify_live_tree(bundle, tree, allowed_extras)
    return candidate


def _write_mutation_failure(
    path: Path,
    requested_source_sha: str,
    target: str | None,
    manifest: dict | None,
    mutation_state: dict[str, object],
    error: BaseException,
    sensitive_values: tuple[str, ...] = (),
) -> dict:
    upload_entered = mutation_state.get("upload_call_entered") is True
    known_revision = mutation_state.get("known_hf_revision")
    if isinstance(known_revision, str) and HEX40.fullmatch(known_revision):
        status = "PARTIAL_AFTER_MUTATION"
    elif upload_entered:
        status = "MUTATION_OUTCOME_UNKNOWN"
        known_revision = None
    else:
        status = "FAILED_BEFORE_MUTATION"
        known_revision = None
    evidence = {
        "schema": "szl.hf-publication-failure/v2",
        "status": status,
        "workflow_stage": "publisher_mutation",
        "requested_source_revision": requested_source_sha,
        "hf_revision": known_revision,
        "previous_hf_revision": mutation_state.get("previous_hf_revision"),
        "bundle_sha256": manifest.get("bundle_sha256") if manifest else None,
        "target": target,
        "upload_call_entered": upload_entered,
        "authoritative_readback_attempted": (
            mutation_state.get("authoritative_readback_attempted") is True
        ),
        "receipt_minted": False,
        "deployment_success": False,
        "diagnostic": _sanitized_diagnostic(error, sensitive_values),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(evidence))
    return evidence


def deploy_bundle(
    bundle: Path,
    source_sha: str,
    result_path: Path,
    config_path: Path = DEFAULT_CONFIG,
    *,
    authorization_path: Path,
    failure_output_path: Path,
    mutation_state: dict[str, object] | None = None,
) -> dict:
    requested_source_sha = str(source_sha or "")
    hf_token = os.environ.get("HF_TOKEN", "")
    state = mutation_state if mutation_state is not None else {}
    state.update(
        {
            "upload_call_entered": False,
            "authoritative_readback_attempted": False,
            "known_hf_revision": None,
            "previous_hf_revision": None,
        }
    )
    config: dict | None = None
    manifest: dict | None = None
    try:
        source_sha = exact_sha(source_sha)
        config = load_config(config_path)
        manifest = validate_bundle(bundle, source_sha, config_path)
        authorization = load_governed_merge(
            authorization_path, source_sha, config_path
        )
        token = hf_token
        if not token:
            raise ContractError(
                "HF_TOKEN is unavailable in the approved repository secret store"
            )
        from huggingface_hub import HfApi

        api = HfApi(token=token)
        deadline = time.monotonic() + DEPLOY_DEADLINE_SECONDS
        before = api.space_info(
            config["target"],
            token=token,
            timeout=_remaining_timeout(
                deadline, HF_REQUEST_TIMEOUT_CAP, "Hugging Face parent lookup"
            ),
        )
        before_sha = exact_sha(before.sha, "observed Hugging Face parent revision")
        state["previous_hf_revision"] = before_sha
        _require_strict_mutation_timer()
        state["upload_call_entered"] = True
        upload_transport = "RETURNED_AUTHORITATIVE_REVISION"
        try:
            commit = _run_with_wall_clock_deadline(
                lambda: api.upload_folder(
                    repo_id=config["target"],
                    repo_type="space",
                    folder_path=str(bundle),
                    token=token,
                    parent_commit=before_sha,
                    delete_patterns="*",
                    commit_message=f"Deploy GitHub source {source_sha}",
                    commit_description=(
                        f"Source: https://github.com/"
                        f"{config['source_repository']}/commit/{source_sha}\n"
                        f"Bundle: {manifest['bundle_sha256']}"
                    ),
                ),
                deadline,
                "Hugging Face upload",
            )
            target_sha = exact_sha(commit.oid, "published Hugging Face revision")
        except Exception as upload_error:
            state["authoritative_readback_attempted"] = True
            try:
                target_sha = _recover_authoritative_revision(
                    bundle,
                    config["target"],
                    before_sha,
                    config["allowed_hf_extras"],
                    time.monotonic() + MUTATION_READBACK_SECONDS,
                )
            except Exception as readback_error:
                raise ContractError(
                    "upload outcome is ambiguous and exact authoritative readback "
                    "did not close it: "
                    f"{_sanitized_diagnostic(readback_error, (hf_token,))}"
                ) from upload_error
            upload_transport = "AMBIGUOUS_RECOVERED_BY_EXACT_READBACK"
        state["known_hf_revision"] = target_sha
        result = {
            "schema": "szl.hf-deploy-result/v1",
            "status": "PUBLISHED_AWAITING_ATTESTATION",
            "source_revision": source_sha,
            "previous_hf_revision": before_sha,
            "hf_revision": target_sha,
            "bundle_sha256": manifest["bundle_sha256"],
            "target": config["target"],
            "upload_transport": upload_transport,
            "authorization": authorization,
        }
        result_path.write_bytes(canonical_json(result))
        failure_output_path.unlink(missing_ok=True)
        return result
    except Exception as error:
        try:
            _write_mutation_failure(
                failure_output_path,
                requested_source_sha,
                config.get("target") if config else None,
                manifest,
                state,
                error,
                (hf_token,),
            )
        except Exception as evidence_error:
            raise ContractError(
                "publisher mutation failed and mandatory machine-readable evidence "
                "could not be persisted; "
                f"mutation={_sanitized_diagnostic(error, (hf_token,))}; "
                "evidence_write="
                f"{_sanitized_diagnostic(evidence_error, (hf_token,))}"
            ) from evidence_error
        raise ContractError(
            "publisher mutation failed closed; canonical machine-readable evidence "
            "was persisted"
        ) from error


def _sanitized_diagnostic(
    error: BaseException, sensitive_values: tuple[str, ...] = ()
) -> str:
    message = f"{type(error).__name__}: {error}"
    for value in sorted(
        {value for value in sensitive_values if value}, key=len, reverse=True
    ):
        message = message.replace(value, "<redacted>")
    message = " ".join(message.replace("\x00", " ").split())
    message = re.sub(
        r"(?i)\bBearer\s+(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)",
        "Bearer <redacted>",
        message,
    )
    message = re.sub(
        r"(?i)([?&](?:access[-_])?(?:token|secret|key)=)[^&#\s]+",
        r"\1<redacted>",
        message,
    )
    message = re.sub(
        r"(?i)([\"']?(?:authorization|token|secret|private[-_ ]?key|api[-_ ]?key)"
        r"[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)",
        r"\1<redacted>",
        message,
    )
    return message[:500]


def _hf_json(url: str, deadline: float) -> object:
    token = os.environ.get("HF_TOKEN", "")
    headers = {"Accept": "application/json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(
            request,
            timeout=_remaining_timeout(deadline, HF_REQUEST_TIMEOUT_CAP, "Hugging Face API"),
        ) as response:
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


def _public_response(url: str, deadline: float) -> tuple[int, bytes, str | None]:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(
            request,
            timeout=_remaining_timeout(deadline, PUBLIC_REQUEST_TIMEOUT_CAP, "public readback"),
        ) as response:
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


def _fetch_public_index(origin: str, source_sha: str, deadline: float) -> bytes:
    source_sha = exact_sha(source_sha)
    query = urllib.parse.urlencode({"source": source_sha})
    root_url = origin + "/?" + query
    status, _, location = _public_response(root_url, deadline)
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
    index_status, body, second_location = _public_response(redirected, deadline)
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
    while True:
        _remaining_timeout(deadline, HF_REQUEST_TIMEOUT_CAP, label)
        try:
            return action()
        except TransientReadbackError as error:
            last_diagnostic = _sanitized_diagnostic(error)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ContractError(
                    f"{label} exhausted the bounded readback deadline; "
                    f"last={last_diagnostic}"
                ) from error
            time.sleep(min(5.0, remaining))


def _wait_for_exact_running(target: str, target_sha: str, deadline: float) -> tuple[str, str]:
    last_stage = last_sha = None
    url = f"https://huggingface.co/api/spaces/{target}"
    while time.monotonic() < deadline:
        info = _retry_transient(
            lambda: _hf_json(url, deadline), deadline, "Space runtime readback"
        )
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
        public_index = _fetch_public_index(origin, source_sha, deadline)
        public_index_sha256 = require_exact_public_index(public_index, expected_index)
        provenance_status, provenance_body, provenance_location = _public_response(
            origin + "/SPACE_PROVENANCE.json?" + query,
            deadline,
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
        "schema": "szl.hf-publication-partial/v2",
        "status": "PARTIAL_AFTER_MUTATION",
        "measured": False,
        "live_success": False,
        "receipt_minted": False,
        "deployment_success": False,
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
    *,
    authorization_path: Path,
    event_path: Path,
    authorization_output_path: Path,
) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    manifest = validate_bundle(bundle, source_sha, config_path)
    initial_authorization = load_governed_merge(
        authorization_path, source_sha, config_path
    )
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if (
        result.get("schema") != "szl.hf-deploy-result/v1"
        or result.get("status") != "PUBLISHED_AWAITING_ATTESTATION"
        or result.get("source_revision") != source_sha
        or result.get("target") != config["target"]
        or result.get("bundle_sha256") != manifest["bundle_sha256"]
        or result.get("authorization") != initial_authorization
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
            lambda: _hf_json(tree_url, deadline), deadline, "Space tree readback"
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
        final_authorization = require_governed_main(
            source_sha,
            event_path,
            authorization_output_path,
            config_path,
        )
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
        "schema": "szl.hf-live-attestation/v2",
        "status": "MEASURED",
        "measured": True,
        "receipt_minted": False,
        "deployment_success": False,
        "source": _source_identity(config, source_sha),
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


def _read_evidence_object(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"workflow evidence is unreadable: {path.name}") from error
    if not isinstance(value, dict):
        raise ContractError(f"workflow evidence is not an object: {path.name}")
    return value


def write_workflow_stage_failure(
    source_sha: str,
    failure_stage: str,
    output_path: Path,
    config_path: Path = DEFAULT_CONFIG,
) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    permitted = {
        "governance_authorization",
        "publisher_input",
        "publisher_executable_rebind",
        "publisher_environment",
        "publisher_mutation",
        "publisher_evidence_upload",
        "measurement_hardening",
        "measurement_input",
        "measurement_executable_rebind",
        "measurement_publisher_evidence_download",
        "measurement_environment",
        "local_measurement",
        "measurement_evidence_upload",
        "attestation_hardening",
        "attestation_checkout",
        "attestation_environment",
        "oidc_attestation",
        "terminal_synthesizer_bootstrap",
        "terminal_evidence_upload",
    }
    if failure_stage not in permitted:
        raise ContractError("workflow failure stage is not recognized")
    evidence = {
        "schema": "szl.hf-workflow-stage-failure/v1",
        "status": "WORKFLOW_STAGE_FAILURE",
        "failure_stage": failure_stage,
        "source": _source_identity(config, source_sha),
        "source_revision": source_sha,
        "hf_revision": None,
        "target": config["target"],
        "receipt_minted": False,
        "deployment_success": False,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json(evidence))
    return evidence


def synthesize_workflow_outcome(
    source_sha: str,
    result_path: Path,
    measurement_path: Path,
    mutation_failure_path: Path,
    partial_path: Path,
    receipt_path: Path,
    workflow_failure_path: Path,
    publish_outcome: str,
    measurement_outcome: str,
    success_evidence_outcome: str,
    oidc_outcome: str,
    attestation_id: str = "",
    attestation_url: str = "",
    force_failure_stage: str = "",
    config_path: Path = DEFAULT_CONFIG,
    *,
    authorization_outcome: str = "success",
    authorization_evidence_outcome: str = "success",
    publisher_input_outcome: str = "success",
    publisher_rebind_outcome: str = "success",
    publisher_environment_outcome: str = "success",
    publisher_evidence_outcome: str = "success",
    publisher_evidence_download_outcome: str = "success",
    measurement_hardening_outcome: str = "success",
    measurement_input_outcome: str = "success",
    measurement_rebind_outcome: str = "success",
    measurement_publisher_evidence_outcome: str = "success",
    measurement_environment_outcome: str = "success",
    measurement_evidence_download_outcome: str = "success",
    attestation_hardening_outcome: str = "success",
    attestation_checkout_outcome: str = "success",
    attestation_environment_outcome: str = "success",
) -> dict:
    source_sha = exact_sha(source_sha)
    config = load_config(config_path)
    expected_source = _source_identity(config, source_sha)
    expected_target = config["target"]
    result = _read_evidence_object(result_path)
    measurement = _read_evidence_object(measurement_path)
    mutation_failure = _read_evidence_object(mutation_failure_path)
    partial = _read_evidence_object(partial_path)
    known_revision = None
    target = None
    for evidence in (measurement, result, partial, mutation_failure):
        if not evidence:
            continue
        candidate = evidence.get("hf_revision")
        if isinstance(candidate, str) and HEX40.fullmatch(candidate):
            known_revision = candidate
        if isinstance(evidence.get("target"), str):
            target = evidence["target"]
        if known_revision and target:
            break
    outcomes = {
        "governance_authorization": authorization_outcome,
        "governance_authorization_evidence": authorization_evidence_outcome,
        "publisher_input": publisher_input_outcome,
        "publisher_executable_rebind": publisher_rebind_outcome,
        "publisher_environment": publisher_environment_outcome,
        "publisher_mutation": publish_outcome,
        "publisher_evidence_upload": publisher_evidence_outcome,
        "publisher_evidence_download": publisher_evidence_download_outcome,
        "measurement_hardening": measurement_hardening_outcome,
        "measurement_input": measurement_input_outcome,
        "measurement_executable_rebind": measurement_rebind_outcome,
        "measurement_publisher_evidence_download": measurement_publisher_evidence_outcome,
        "measurement_environment": measurement_environment_outcome,
        "local_measurement": measurement_outcome,
        "measurement_evidence_upload": success_evidence_outcome,
        "measurement_evidence_download": measurement_evidence_download_outcome,
        "attestation_hardening": attestation_hardening_outcome,
        "attestation_checkout": attestation_checkout_outcome,
        "attestation_environment": attestation_environment_outcome,
        "oidc_attestation": oidc_outcome,
    }
    observed_source = measurement.get("source") if measurement else None
    failure_stage = force_failure_stage
    if not failure_stage:
        failure_stage = next(
            (stage for stage, outcome in outcomes.items() if outcome != "success"),
            "",
        )
    if not failure_stage and (
        not measurement
        or measurement.get("schema") != "szl.hf-live-attestation/v2"
        or measurement.get("status") != "MEASURED"
        or observed_source != expected_source
        or measurement.get("source_revision") != source_sha
        or measurement.get("hf_revision") != known_revision
        or measurement.get("target") != expected_target
        or measurement.get("receipt_minted") is not False
        or measurement.get("deployment_success") is not False
    ):
        failure_stage = "local_measurement_schema"
    if not failure_stage and (not attestation_id or not attestation_url):
        failure_stage = "oidc_attestation_outputs"
    if failure_stage:
        evidence = {
            "schema": "szl.hf-workflow-stage-failure/v1",
            "status": "WORKFLOW_STAGE_FAILURE",
            "failure_stage": failure_stage,
            "source": observed_source,
            "expected_source": expected_source,
            "source_revision": source_sha,
            "hf_revision": known_revision,
            "target": target,
            "expected_target": expected_target,
            "mutation_status": (
                mutation_failure.get("status") if mutation_failure else None
            ),
            "partial_status": partial.get("status") if partial else None,
            "step_outcomes": outcomes,
            "receipt_minted": False,
            "deployment_success": False,
        }
        workflow_failure_path.parent.mkdir(parents=True, exist_ok=True)
        workflow_failure_path.write_bytes(canonical_json(evidence))
        receipt_path.unlink(missing_ok=True)
        return evidence
    assert measurement is not None and known_revision is not None
    measurement_bytes = measurement_path.read_bytes()
    receipt = {
        "schema": "szl.hf-oidc-receipt/v1",
        "status": "OIDC_ATTESTED_DEPLOYMENT",
        "source": expected_source,
        "source_revision": source_sha,
        "hf_revision": known_revision,
        "target": expected_target,
        "measurement": {
            "path": measurement_path.name,
            "sha256": sha256_bytes(measurement_bytes),
            "bytes": len(measurement_bytes),
            "status": "MEASURED",
        },
        "github_oidc_attestation": {
            "attestation_id": attestation_id,
            "attestation_url": attestation_url,
        },
        "receipt_minted": True,
        "deployment_success": True,
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(canonical_json(receipt))
    workflow_failure_path.unlink(missing_ok=True)
    return receipt


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
    guard.add_argument("--event", type=Path, required=True)
    guard.add_argument("--output", type=Path, required=True)
    guard.add_argument("--failure-output", type=Path, required=True)
    pr_body = subparsers.add_parser("pr-body")
    pr_body.add_argument("--source-sha", required=True)
    pr_body.add_argument("--event", type=Path, required=True)
    dco = subparsers.add_parser("dco")
    dco.add_argument("--base-sha", required=True)
    dco.add_argument("--head-sha", required=True)
    deploy = subparsers.add_parser("deploy")
    deploy.add_argument("--bundle", type=Path, required=True)
    deploy.add_argument("--source-sha", required=True)
    deploy.add_argument("--result", type=Path, required=True)
    deploy.add_argument("--authorization", type=Path, required=True)
    deploy.add_argument("--failure-output", type=Path, required=True)
    attest = subparsers.add_parser("attest")
    attest.add_argument("--bundle", type=Path, required=True)
    attest.add_argument("--source-sha", required=True)
    attest.add_argument("--result", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)
    attest.add_argument("--failure-output", type=Path, required=True)
    attest.add_argument("--authorization", type=Path, required=True)
    attest.add_argument("--event", type=Path, required=True)
    attest.add_argument("--authorization-output", type=Path, required=True)
    attest.add_argument("--timeout", type=int)
    stage_failure = subparsers.add_parser("stage-failure")
    stage_failure.add_argument("--source-sha", required=True)
    stage_failure.add_argument("--stage", required=True)
    stage_failure.add_argument("--output", type=Path, required=True)
    outcome = subparsers.add_parser("workflow-outcome")
    outcome.add_argument("--source-sha", required=True)
    outcome.add_argument("--result", type=Path, required=True)
    outcome.add_argument("--measurement", type=Path, required=True)
    outcome.add_argument("--mutation-failure", type=Path, required=True)
    outcome.add_argument("--partial", type=Path, required=True)
    outcome.add_argument("--receipt", type=Path, required=True)
    outcome.add_argument("--workflow-failure", type=Path, required=True)
    outcome.add_argument("--publish-outcome", required=True)
    outcome.add_argument("--measurement-outcome", required=True)
    outcome.add_argument("--success-evidence-outcome", required=True)
    outcome.add_argument("--oidc-outcome", required=True)
    outcome.add_argument("--authorization-outcome", default="success")
    outcome.add_argument("--authorization-evidence-outcome", default="success")
    outcome.add_argument("--publisher-input-outcome", default="success")
    outcome.add_argument("--publisher-rebind-outcome", default="success")
    outcome.add_argument("--publisher-environment-outcome", default="success")
    outcome.add_argument("--publisher-evidence-outcome", default="success")
    outcome.add_argument("--publisher-evidence-download-outcome", default="success")
    outcome.add_argument("--measurement-hardening-outcome", default="success")
    outcome.add_argument("--measurement-input-outcome", default="success")
    outcome.add_argument("--measurement-rebind-outcome", default="success")
    outcome.add_argument("--measurement-publisher-evidence-outcome", default="success")
    outcome.add_argument("--measurement-environment-outcome", default="success")
    outcome.add_argument("--measurement-evidence-download-outcome", default="success")
    outcome.add_argument("--attestation-hardening-outcome", default="success")
    outcome.add_argument("--attestation-checkout-outcome", default="success")
    outcome.add_argument("--attestation-environment-outcome", default="success")
    outcome.add_argument("--attestation-id", default="")
    outcome.add_argument("--attestation-url", default="")
    outcome.add_argument("--force-failure-stage", default="")
    args = parser.parse_args()
    if args.command == "build":
        value = build_bundle(args.output, args.source_sha, args.config)
    elif args.command == "validate":
        value = validate_bundle(args.bundle, args.source_sha, args.config)
    elif args.command == "guard":
        value = require_governed_main(
            args.source_sha,
            args.event,
            args.output,
            args.config,
            failure_output_path=args.failure_output,
        )
    elif args.command == "pr-body":
        value = validate_pr_body_event(args.source_sha, args.event, args.config)
    elif args.command == "dco":
        value = validate_dco_range(args.base_sha, args.head_sha)
    elif args.command == "deploy":
        value = deploy_bundle(
            args.bundle,
            args.source_sha,
            args.result,
            args.config,
            authorization_path=args.authorization,
            failure_output_path=args.failure_output,
        )
    elif args.command == "attest":
        value = attest_bundle(
            args.bundle,
            args.source_sha,
            args.result,
            args.output,
            args.timeout,
            args.config,
            args.failure_output,
            authorization_path=args.authorization,
            event_path=args.event,
            authorization_output_path=args.authorization_output,
        )
    elif args.command == "stage-failure":
        value = write_workflow_stage_failure(
            args.source_sha, args.stage, args.output, args.config
        )
    else:
        value = synthesize_workflow_outcome(
            args.source_sha,
            args.result,
            args.measurement,
            args.mutation_failure,
            args.partial,
            args.receipt,
            args.workflow_failure,
            args.publish_outcome,
            args.measurement_outcome,
            args.success_evidence_outcome,
            args.oidc_outcome,
            args.attestation_id,
            args.attestation_url,
            args.force_failure_stage,
            args.config,
            authorization_outcome=args.authorization_outcome,
            authorization_evidence_outcome=args.authorization_evidence_outcome,
            publisher_input_outcome=args.publisher_input_outcome,
            publisher_rebind_outcome=args.publisher_rebind_outcome,
            publisher_environment_outcome=args.publisher_environment_outcome,
            publisher_evidence_outcome=args.publisher_evidence_outcome,
            publisher_evidence_download_outcome=args.publisher_evidence_download_outcome,
            measurement_hardening_outcome=args.measurement_hardening_outcome,
            measurement_input_outcome=args.measurement_input_outcome,
            measurement_rebind_outcome=args.measurement_rebind_outcome,
            measurement_publisher_evidence_outcome=args.measurement_publisher_evidence_outcome,
            measurement_environment_outcome=args.measurement_environment_outcome,
            measurement_evidence_download_outcome=args.measurement_evidence_download_outcome,
            attestation_hardening_outcome=args.attestation_hardening_outcome,
            attestation_checkout_outcome=args.attestation_checkout_outcome,
            attestation_environment_outcome=args.attestation_environment_outcome,
        )
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL-CLOSED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
