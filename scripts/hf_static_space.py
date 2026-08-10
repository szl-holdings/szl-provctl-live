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


def _load_event(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("GitHub push event is unreadable") from error
    if not isinstance(value, dict):
        raise ContractError("GitHub push event is not an object")
    return value


def _complete_inventory(rows: object, key: str, label: str) -> list[dict]:
    if not isinstance(rows, dict) or not isinstance(rows.get(key), list):
        raise ContractError(f"{label} inventory is unavailable")
    items = rows[key]
    total_count = rows.get("total_count")
    if (
        type(total_count) is not int
        or total_count != len(items)
        or total_count > 100
        or any(not isinstance(item, dict) for item in items)
    ):
        raise ContractError(f"{label} inventory is incomplete or malformed")
    return items


def _exact_job_url(value: object, repository: str, run_id: int, job_id: int) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urllib.parse.urlsplit(value)
    return (
        parsed.scheme == "https"
        and parsed.netloc == "github.com"
        and parsed.path
        == f"/{repository}/actions/runs/{run_id}/job/{job_id}"
        and not parsed.query
        and not parsed.fragment
    )


def _require_successful_checks(
    rows: object, repository: str, head_sha: str, release_run_id: int
) -> list[dict]:
    check_runs = _complete_inventory(rows, "check_runs", "exact-head check-run")
    evidence: list[dict] = []
    for name, integration_id in sorted(REQUIRED_STATUS_CONTEXTS.items()):
        matches = [
            row
            for row in check_runs
            if row.get("name") == name
            and row.get("head_sha") == head_sha
            and isinstance(row.get("app"), dict)
            and row["app"].get("id") == integration_id
            and type(row.get("id")) is int
            and row["id"] > 0
            and _exact_job_url(
                row.get("details_url"), repository, release_run_id, row["id"]
            )
        ]
        if not matches:
            raise ContractError(
                f"required exact publisher-workflow check is unavailable: {name}"
            )
        selected = max(matches, key=lambda row: row["id"])
        if (
            selected.get("status") != "completed"
            or selected.get("conclusion") != "success"
        ):
            raise ContractError(
                f"latest exact publisher-workflow check did not succeed: {name}"
            )
        evidence.append(
            {
                "app_id": integration_id,
                "check_run_id": selected.get("id"),
                "conclusion": "success",
                "head_revision": head_sha,
                "name": name,
                "workflow_run_id": release_run_id,
            }
        )
    return evidence


def _require_exact_pull_request_workflow(
    rows: object,
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
) -> dict[str, object]:
    workflow_runs = _complete_inventory(rows, "workflow_runs", "workflow-run")
    matches = [
        row
        for row in workflow_runs
        if row.get("workflow_id") == workflow_id
        and row.get("name") == workflow_name
        and row.get("path") == workflow_path
        and row.get("event") == "pull_request"
        and row.get("head_sha") == head_sha
        and isinstance(row.get("repository"), dict)
        and row["repository"].get("full_name") == repository
        and row["repository"].get("id") == repository_id
    ]
    if not matches:
        raise ContractError(f"exact {label} did not run for this head")
    if any(
        type(row.get("id")) is not int
        or row["id"] <= 0
        or type(row.get("run_attempt")) is not int
        or row["run_attempt"] <= 0
        for row in matches
    ):
        raise ContractError(f"exact {label} identity is malformed")
    selected = max(matches, key=lambda row: row["id"])
    pull_requests = selected.get("pull_requests")
    if not isinstance(pull_requests, list) or len(pull_requests) != 1:
        raise ContractError(f"exact {label} is not bound to one pull request")
    run_pull = pull_requests[0]
    run_head = run_pull.get("head") if isinstance(run_pull, dict) else None
    run_base = run_pull.get("base") if isinstance(run_pull, dict) else None
    if (
        not isinstance(run_pull, dict)
        or run_pull.get("number") != pull_number
        or not isinstance(run_head, dict)
        or run_head.get("ref") != head_ref
        or run_head.get("sha") != head_sha
        or not isinstance(run_head.get("repo"), dict)
        or run_head["repo"].get("id") != repository_id
        or not isinstance(run_base, dict)
        or run_base.get("ref") != "main"
        or run_base.get("sha") != base_sha
        or not isinstance(run_base.get("repo"), dict)
        or run_base["repo"].get("id") != repository_id
    ):
        raise ContractError(f"exact {label} pull-request tuple is not exact")
    if (
        selected.get("status") != "completed"
        or selected.get("conclusion") != "success"
    ):
        raise ContractError(f"latest exact {label} did not succeed")
    return {
        "base_revision": base_sha,
        "conclusion": "success",
        "event": "pull_request",
        "head_ref": head_ref,
        "head_revision": head_sha,
        "name": workflow_name,
        "path": workflow_path,
        "pull_request_number": pull_number,
        "repository_id": repository_id,
        "run_attempt": selected.get("run_attempt"),
        "run_id": selected.get("id"),
        "status": "completed",
        "workflow_id": workflow_id,
    }


def _require_release_workflow(
    rows: object,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
) -> dict[str, object]:
    return _require_exact_pull_request_workflow(
        rows,
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
    )


def _require_boundary_workflow(
    rows: object,
    repository: str,
    repository_id: int,
    pull_number: int,
    base_sha: str,
    head_ref: str,
    head_sha: str,
) -> dict[str, object]:
    return _require_exact_pull_request_workflow(
        rows,
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
    )


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
        associated = _request_json(
            f"{api_root}/repos/{repository}/commits/{source_sha}/pulls", token
        )
        if not isinstance(associated, list):
            raise ContractError("associated pull-request evidence is unavailable")
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
        if not isinstance(pull, dict) or pull.get("id") != candidate.get("id"):
            raise ContractError("merged pull-request readback is not exact")
        head = pull.get("head")
        base = pull.get("base")
        merged_by = pull.get("merged_by")
        head_sha = exact_sha((head or {}).get("sha"), "pull-request head revision")
        head_ref = (head or {}).get("ref")
        if (
            pull.get("state") != "closed"
            or not pull.get("merged")
            or not pull.get("merged_at")
            or pull.get("merge_commit_sha") != source_sha
            or not isinstance(base, dict)
            or base.get("ref") != "main"
            or base.get("sha") != before_sha
            or not isinstance(base.get("repo"), dict)
            or base["repo"].get("full_name") != repository
            or not isinstance(head, dict)
            or not isinstance(head_ref, str)
            or not head_ref
            or not isinstance(head.get("repo"), dict)
            or head["repo"].get("full_name") != repository
            or head["repo"].get("id") != expected_repository_id
            or base["repo"].get("id") != expected_repository_id
            or not isinstance(merged_by, dict)
            or not isinstance(merged_by.get("login"), str)
        ):
            raise ContractError("merged pull-request tuple is not exact")
        query = urllib.parse.urlencode(
            {"event": "pull_request", "head_sha": head_sha, "per_page": 100}
        )
        workflow_runs = _request_json(
            f"{api_root}/repos/{repository}/actions/runs?{query}", token
        )
        release_workflow = _require_release_workflow(
            workflow_runs,
            repository,
            expected_repository_id,
            number,
            before_sha,
            head_ref,
            head_sha,
        )
        boundary = _require_boundary_workflow(
            workflow_runs,
            repository,
            expected_repository_id,
            number,
            before_sha,
            head_ref,
            head_sha,
        )
        check_runs = _request_json(
            f"{api_root}/repos/{repository}/commits/{head_sha}/check-runs?per_page=100",
            token,
        )
        checks = _require_successful_checks(
            check_runs, repository, head_sha, int(release_workflow["run_id"])
        )
        evidence = {
            "schema": "szl.github-governed-merge/v2",
            "status": "AUTHORIZED_EXACT_GOVERNED_MERGE",
            "source_revision": source_sha,
            "repository": {
                "default_branch": "main",
                "full_name": repository,
                "id": expected_repository_id,
            },
            "push": {"before": before_sha, "after": source_sha},
            "pull_request": {
                "base_revision": before_sha,
                "head_ref": head_ref,
                "head_revision": head_sha,
                "merge_revision": source_sha,
                "merged_at": pull["merged_at"],
                "merged_by": merged_by["login"],
                "number": number,
            },
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
) -> bool:
    return (
        isinstance(workflow, dict)
        and set(workflow)
        == {
            "base_revision",
            "conclusion",
            "event",
            "head_ref",
            "head_revision",
            "name",
            "path",
            "pull_request_number",
            "repository_id",
            "run_attempt",
            "run_id",
            "status",
            "workflow_id",
        }
        and workflow.get("workflow_id") == workflow_id
        and workflow.get("name") == workflow_name
        and workflow.get("path") == workflow_path
        and workflow.get("event") == "pull_request"
        and workflow.get("repository_id") == repository_id
        and workflow.get("pull_request_number") == pull_number
        and workflow.get("base_revision") == base_sha
        and workflow.get("head_ref") == head_ref
        and workflow.get("head_revision") == head_sha
        and workflow.get("status") == "completed"
        and workflow.get("conclusion") == "success"
        and type(workflow.get("run_id")) is int
        and workflow["run_id"] > 0
        and type(workflow.get("run_attempt")) is int
        and workflow["run_attempt"] > 0
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
    repository = evidence.get("repository")
    push = evidence.get("push")
    pull = evidence.get("pull_request")
    checks = evidence.get("required_checks")
    release_workflow = evidence.get("release_workflow")
    workflow = evidence.get("required_workflow")
    expected_repository = config["source_repository"]
    expected_checks = {
        (name, integration_id)
        for name, integration_id in REQUIRED_STATUS_CONTEXTS.items()
    }
    checks_are_exact = isinstance(checks, list) and all(
        isinstance(row, dict)
        and set(row)
        == {
            "app_id",
            "check_run_id",
            "conclusion",
            "head_revision",
            "name",
            "workflow_run_id",
        }
        for row in checks
    )
    observed_checks = {
        (row.get("name"), row.get("app_id"))
        for row in checks
        if isinstance(row, dict)
        and row.get("head_revision") == (pull or {}).get("head_revision")
        and row.get("conclusion") == "success"
        and type(row.get("check_run_id")) is int
        and row.get("check_run_id") > 0
        and row.get("workflow_run_id") == (release_workflow or {}).get("run_id")
    } if isinstance(checks, list) else set()
    pull_number = (pull or {}).get("number")
    pull_base = (pull or {}).get("base_revision")
    pull_head_ref = (pull or {}).get("head_ref")
    pull_head = (pull or {}).get("head_revision")
    repository_id = (repository or {}).get("id")
    if (
        set(evidence) != {
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
        or evidence.get("schema") != "szl.github-governed-merge/v2"
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
        or not isinstance(pull, dict)
        or set(pull) != {
            "base_revision",
            "head_ref",
            "head_revision",
            "merge_revision",
            "merged_at",
            "merged_by",
            "number",
        }
        or pull.get("base_revision") != push.get("before")
        or not isinstance(pull.get("head_ref"), str)
        or not pull["head_ref"]
        or not isinstance(pull.get("head_revision"), str)
        or not HEX40.fullmatch(pull["head_revision"])
        or pull.get("merge_revision") != source_sha
        or not isinstance(pull.get("merged_at"), str)
        or not pull["merged_at"]
        or not isinstance(pull.get("merged_by"), str)
        or not pull["merged_by"]
        or type(pull.get("number")) is not int
        or pull["number"] <= 0
        or not isinstance(checks, list)
        or len(checks) != len(expected_checks)
        or not checks_are_exact
        or observed_checks != expected_checks
        or not _workflow_evidence_is_exact(
            release_workflow,
            workflow_id=TARGET_RELEASE_WORKFLOW_IDS[expected_repository],
            workflow_name=RELEASE_WORKFLOW_NAME,
            workflow_path=RELEASE_WORKFLOW_PATH,
            repository_id=repository_id,
            pull_number=pull_number,
            base_sha=pull_base,
            head_ref=pull_head_ref,
            head_sha=pull_head,
        )
        or not _workflow_evidence_is_exact(
            workflow,
            workflow_id=TARGET_REQUIRED_WORKFLOW_IDS[expected_repository],
            workflow_name=REQUIRED_WORKFLOW_NAME,
            workflow_path=REQUIRED_WORKFLOW_PATH,
            repository_id=repository_id,
            pull_number=pull_number,
            base_sha=pull_base,
            head_ref=pull_head_ref,
            head_sha=pull_head,
        )
    ):
        raise ContractError("governed-merge evidence is not bound to this release")
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
        "diagnostic": _sanitized_diagnostic(error),
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
        token = os.environ.get("HF_TOKEN", "")
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
                    f"did not close it: {_sanitized_diagnostic(readback_error)}"
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
            )
        except Exception as evidence_error:
            raise ContractError(
                "publisher mutation failed and mandatory machine-readable evidence "
                "could not be persisted; "
                f"mutation={_sanitized_diagnostic(error)}; "
                f"evidence_write={_sanitized_diagnostic(evidence_error)}"
            ) from evidence_error
        raise ContractError(
            "publisher mutation failed closed; canonical machine-readable evidence "
            "was persisted"
        ) from error


def _sanitized_diagnostic(error: BaseException) -> str:
    message = f"{type(error).__name__}: {error}"
    message = " ".join(message.replace("\x00", " ").split())
    message = re.sub(
        r"(?i)(authorization|token|secret|private[-_ ]?key)(\s*[:=]\s*)\S+",
        r"\1\2<redacted>",
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
        "publisher_environment",
        "publisher_mutation",
        "publisher_evidence_upload",
        "local_measurement",
        "measurement_evidence_upload",
        "oidc_attestation",
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
    publisher_environment_outcome: str = "success",
    publisher_evidence_outcome: str = "success",
    publisher_evidence_download_outcome: str = "success",
    measurement_evidence_download_outcome: str = "success",
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
        "publisher_environment": publisher_environment_outcome,
        "publisher_mutation": publish_outcome,
        "publisher_evidence_upload": publisher_evidence_outcome,
        "publisher_evidence_download": publisher_evidence_download_outcome,
        "local_measurement": measurement_outcome,
        "measurement_evidence_upload": success_evidence_outcome,
        "measurement_evidence_download": measurement_evidence_download_outcome,
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
    outcome.add_argument("--publisher-environment-outcome", default="success")
    outcome.add_argument("--publisher-evidence-outcome", default="success")
    outcome.add_argument("--publisher-evidence-download-outcome", default="success")
    outcome.add_argument("--measurement-evidence-download-outcome", default="success")
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
            publisher_environment_outcome=args.publisher_environment_outcome,
            publisher_evidence_outcome=args.publisher_evidence_outcome,
            publisher_evidence_download_outcome=args.publisher_evidence_download_outcome,
            measurement_evidence_download_outcome=args.measurement_evidence_download_outcome,
        )
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"FAIL-CLOSED: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
