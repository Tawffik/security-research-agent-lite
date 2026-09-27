"""Download + extract BugBountyCI GitHub Actions artifacts; discover recon JSON.

Lite does not run recon — only consumes BBCI artifacts.
"""

from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class BbciArtifactResult:
    status: str  # ok | blocked | error
    reason: str = ""
    extract_dir: str = ""
    recon_path: str = ""
    candidates: list[str] = field(default_factory=list)
    artifact_name: str = ""
    run_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _api_request(url: str, token: str) -> tuple[int, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "security-research-agent-lite",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()
            code = resp.status
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")[:500]
    except Exception as e:  # noqa: BLE001
        return 0, str(type(e).__name__)
    try:
        return code, json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return code, raw


def list_run_artifacts(repo: str, run_id: str, token: str) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"
    code, data = _api_request(url, token)
    if code != 200 or not isinstance(data, dict):
        return []
    return list(data.get("artifacts") or [])


def download_artifact_zip(
    repo: str,
    artifact_id: str,
    token: str,
    dest_zip: Path,
) -> tuple[bool, str]:
    """
    GitHub returns 302 to a signed URL for artifact zips.
    Re-sending Authorization to that host causes http_401 — strip auth on redirect.
    """
    url = f"https://api.github.com/repos/{repo}/actions/artifacts/{artifact_id}/zip"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "security-research-agent-lite",
    }
    try:
        # Manual first request without auto-redirect
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: A002
                return None

        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with opener.open(req, timeout=120) as resp:
                dest_zip.parent.mkdir(parents=True, exist_ok=True)
                dest_zip.write_bytes(resp.read())
            return True, "ok"
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303, 307, 308):
                return False, f"http_{e.code}"
            loc = e.headers.get("Location") or e.headers.get("location")
            if not loc:
                return False, f"http_{e.code}_no_location"
            # Second hop: signed URL — no Authorization header
            req2 = urllib.request.Request(
                loc,
                headers={"User-Agent": "security-research-agent-lite"},
                method="GET",
            )
            with urllib.request.urlopen(req2, timeout=300) as resp2:
                dest_zip.parent.mkdir(parents=True, exist_ok=True)
                dest_zip.write_bytes(resp2.read())
            return True, "ok"
    except urllib.error.HTTPError as e:
        return False, f"http_{e.code}"
    except Exception as e:  # noqa: BLE001
        return False, type(e).__name__


def extract_zip(zip_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)


def _score_recon_candidate(path: Path) -> int:
    name = path.name.lower()
    score = 0
    for token in ("recon", "normalized", "endpoints", "hosts", "bbci", "results", "asset"):
        if token in name:
            score += 10
    if name.endswith(".json"):
        score += 5
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return score
    if not isinstance(data, dict):
        return score
    for key in (
        "endpoints",
        "urls",
        "hosts",
        "primary_host",
        "host",
        "observations",
        "http_observations",
        "technologies",
        "actors",
        "resources",
    ):
        if key in data:
            score += 20
    # nested bundle
    for wrap in ("bundle", "recon", "artifact", "data"):
        inner = data.get(wrap)
        if isinstance(inner, dict) and any(
            k in inner for k in ("endpoints", "hosts", "urls", "primary_host")
        ):
            score += 15
    return score



def _read_json_or_jsonl(path: Path) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows if rows else None


def compose_bbci_recon(extract_dir: Path) -> Optional[Path]:
    """
    Build a single Lite-friendly recon JSON from a typical BBCI results tree.
    Writes artifacts/bbci_composed_recon.json under extract_dir.
    """
    extract_dir = Path(extract_dir)
    profile = None
    for cand in [
        extract_dir / "smart-fuzzing" / "target_profile.json",
        extract_dir / "target_profile.json",
    ]:
        if cand.is_file():
            try:
                profile = json.loads(cand.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                profile = None
            break

    hosts: list[str] = []
    endpoints: list[Any] = []
    technologies: list[str] = []
    observations: list[dict[str, Any]] = []

    if isinstance(profile, dict):
        hosts.extend(list(profile.get("hosts") or []))
        technologies.extend(list(profile.get("technologies") or []))
        target = profile.get("target") or profile.get("primary_host") or ""
    else:
        target = ""

    # endpoints from ai_infra or jsonl
    for rel in (
        "ai_infra/endpoints.json",
        "endpoints.json",
        "live/live.json",
        "detection/parameter_intelligence.json",
    ):
        fp = extract_dir / rel
        if not fp.is_file():
            continue
        data = _read_json_or_jsonl(fp)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    endpoints.append(item)
                    u = str(item.get("url") or item.get("uri") or "")
                    if u:
                        endpoints.append(u)
                elif isinstance(item, str):
                    endpoints.append(item)
        elif isinstance(data, dict):
            for key in ("endpoints", "urls", "results", "data"):
                for item in data.get(key) or []:
                    endpoints.append(item)

    # live hosts jsonl
    live = extract_dir / "live" / "live.json"
    if live.is_file():
        data = _read_json_or_jsonl(live)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    hosts.append(item)
                elif isinstance(item, dict):
                    hosts.append(str(item.get("host") or item.get("url") or item.get("input") or ""))

    # tech jsonl
    tech = extract_dir / "live" / "tech.json"
    if tech.is_file():
        data = _read_json_or_jsonl(tech)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    technologies.append(item)
                elif isinstance(item, dict):
                    technologies.append(str(item.get("tech") or item.get("name") or item.get("technology") or ""))

    if not target and hosts:
        target = hosts[0]

    if not target and not hosts and not endpoints:
        return None

    composed = {
        "schema_version": "bbci_composed_v1",
        "primary_host": target,
        "target": target,
        "hosts": [h for h in hosts if h],
        "endpoints": endpoints[:5000],
        "technologies": [t for t in technologies if t],
        "observations": observations,
        "notes": "composed_from_bbci_artifact_tree",
        "provenance": {"composer": "agent_lite.recon.bbci_artifact.compose_bbci_recon"},
    }
    out = extract_dir / "bbci_composed_recon.json"
    out.write_text(json.dumps(composed, indent=2), encoding="utf-8")
    return out


def discover_recon_json(extract_dir: Path) -> tuple[Optional[Path], list[str]]:
    candidates: list[tuple[int, Path]] = []
    for p in extract_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".json", ".jsonl"):
            continue
        if p.name.startswith("."):
            continue
        score = _score_recon_candidate(p)
        if score > 0:
            candidates.append((score, p))
    candidates.sort(key=lambda x: (-x[0], str(x[1])))
    paths = [str(p) for _, p in candidates]
    if not candidates:
        return None, paths
    return candidates[0][1], paths


def resolve_bbci_artifact(
    *,
    repo: str = "Tawffik/BugBountyCI",
    run_id: str = "",
    artifact_id: str = "",
    artifact_name: str = "",
    token: str = "",
    work_dir: str | Path = "artifacts/bbci_download",
) -> BbciArtifactResult:
    """
    Download BBCI artifact by run_id (+ optional name/id), extract, discover recon JSON.
    """
    token = (token or os.environ.get("BBCI_READ_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()
    if not token:
        return BbciArtifactResult(status="blocked", reason="missing_bbci_read_token")
    if not run_id and not artifact_id:
        return BbciArtifactResult(status="blocked", reason="missing_run_id_or_artifact_id")

    work = Path(work_dir)
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    selected: Optional[dict[str, Any]] = None
    if artifact_id:
        selected = {"id": int(artifact_id) if str(artifact_id).isdigit() else artifact_id, "name": artifact_name or artifact_id}
    else:
        arts = list_run_artifacts(repo, str(run_id), token)
        if not arts:
            return BbciArtifactResult(
                status="blocked",
                reason="no_artifacts_or_unauthorized",
                run_id=str(run_id),
            )
        if artifact_name:
            for a in arts:
                if a.get("name") == artifact_name or artifact_name in str(a.get("name") or ""):
                    selected = a
                    break
            if selected is None:
                return BbciArtifactResult(
                    status="blocked",
                    reason="artifact_name_not_found",
                    run_id=str(run_id),
                    candidates=[str(a.get("name")) for a in arts],
                )
        else:
            # Prefer largest / name containing results or recon
            def rank(a: dict) -> tuple:
                name = str(a.get("name") or "").lower()
                return (
                    0 if "result" in name or "recon" in name else 1,
                    -(int(a.get("size_in_bytes") or 0)),
                )

            arts_sorted = sorted(arts, key=rank)
            selected = arts_sorted[0]

    aid = str(selected.get("id") or artifact_id)
    aname = str(selected.get("name") or artifact_name or aid)
    zip_path = work / f"{aid}.zip"
    ok, reason = download_artifact_zip(repo, aid, token, zip_path)
    if not ok:
        return BbciArtifactResult(
            status="blocked",
            reason=f"download_failed:{reason}",
            run_id=str(run_id),
            artifact_name=aname,
        )

    extract_dir = work / "extracted"
    try:
        extract_zip(zip_path, extract_dir)
    except Exception as e:  # noqa: BLE001
        return BbciArtifactResult(status="error", reason=f"extract_failed:{type(e).__name__}")

    composed = compose_bbci_recon(extract_dir)
    recon, cand = discover_recon_json(extract_dir)
    # Prefer composed bundle when available (real BBCI multi-file layout)
    if composed is not None and composed.is_file():
        recon = composed
        if str(composed) not in cand:
            cand = [str(composed)] + cand
    if recon is None:
        return BbciArtifactResult(
            status="blocked",
            reason="missing_or_invalid_recon",
            extract_dir=str(extract_dir),
            candidates=cand,
            artifact_name=aname,
            run_id=str(run_id),
        )
    return BbciArtifactResult(
        status="ok",
        extract_dir=str(extract_dir),
        recon_path=str(recon),
        candidates=cand[:20],
        artifact_name=aname,
        run_id=str(run_id),
    )


def write_scope_from_recon(recon_path: Path, dest: Path, *, program: str = "bbci-import") -> Path:
    """
    Build fail-closed GET-only scope from normalized recon hosts.
    For analysis/synthetic only — does not enable live mutations.
    """
    import yaml
    from agent_lite.recon.adapter import ReconAdapter

    n = ReconAdapter().from_file(recon_path)
    hosts = list(dict.fromkeys([n.primary_host] + list(n.hosts)))
    in_scope = []
    for h in hosts:
        if not h:
            continue
        in_scope.append({"host": h, "methods": ["GET", "HEAD", "OPTIONS"]})
    # Always allow synthetic lab hosts so analysis/scenario discrimination still runs
    lab_hosts = ["api.acme-demo.test", "*.acme-demo.test"]
    existing = {str(x.get("host")) for x in in_scope}
    for h in lab_hosts:
        if h not in existing:
            in_scope.append({"host": h, "methods": ["GET", "HEAD", "OPTIONS"]})
    doc = {
        "program": program,
        "in_scope": in_scope[:200],
        "out_of_scope": [],
        "max_risk": "medium",
        "allow_mutations": False,
        "notes": "auto_from_bbci_recon_analysis_only",
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return dest


def main(argv: Optional[list[str]] = None) -> int:

    import argparse

    p = argparse.ArgumentParser(description="Fetch BugBountyCI artifact and resolve recon path")
    p.add_argument("--repo", default=os.environ.get("BBCI_REPO", "Tawffik/BugBountyCI"))
    p.add_argument("--run-id", default=os.environ.get("BBCI_RUN_ID", ""))
    p.add_argument("--artifact-id", default=os.environ.get("BBCI_ARTIFACT_ID", ""))
    p.add_argument("--artifact-name", default=os.environ.get("BBCI_ARTIFACT_NAME", ""))
    p.add_argument("--work-dir", default="artifacts/bbci_download")
    p.add_argument("--print-path-only", action="store_true")
    args = p.parse_args(argv)
    result = resolve_bbci_artifact(
        repo=args.repo,
        run_id=args.run_id,
        artifact_id=args.artifact_id,
        artifact_name=args.artifact_name,
        work_dir=args.work_dir,
    )
    if args.print_path_only and result.status == "ok":
        print(result.recon_path)
        return 0
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
