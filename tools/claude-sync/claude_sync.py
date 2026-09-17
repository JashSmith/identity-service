#!/usr/bin/env python3

import argparse
import filecmp
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ARCHIVE_NAME = ".claude-sync"


def get_repo_root() -> Path:
    try:
        result = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()

        if result:
            return Path(result).resolve()
    except Exception:
        pass

    return Path.cwd().resolve()


def get_claude_home() -> Path:
    custom = os.environ.get("CLAUDE_CONFIG_DIR")
    if custom:
        return Path(custom).expanduser().resolve()

    return Path.home() / ".claude"


def get_projects_root() -> Path:
    return get_claude_home() / "projects"


def get_archive_paths(repo: Path):
    archive = repo / ARCHIVE_NAME
    sessions = archive / "sessions"
    conflicts = archive / "conflicts"
    manifest = archive / "manifest.json"

    sessions.mkdir(parents=True, exist_ok=True)
    conflicts.mkdir(parents=True, exist_ok=True)

    return archive, sessions, conflicts, manifest


def claude_project_slug(path: Path) -> str:
    # Documented default Claude Code behavior for normal path lengths.
    return re.sub(r"[^A-Za-z0-9]", "-", str(path.resolve()))


def path_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except Exception:
        return False


def get_cwd_from_transcript(path: Path):
    """
    Best-effort only.
    Used for discovery, not for modifying the transcript.
    Claude's JSONL structure is internal and may change.
    """
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i > 100:
                    break

                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                cwd = obj.get("cwd")
                if isinstance(cwd, str) and cwd:
                    return cwd
    except Exception:
        pass

    return None


def find_project_session_dirs(repo: Path):
    projects_root = get_projects_root()

    if not projects_root.exists():
        return []

    result = set()

    # Fast path: Claude's normal encoded project directory.
    for p in {repo, Path.cwd().resolve()}:
        candidate = projects_root / claude_project_slug(p)
        if candidate.exists():
            result.add(candidate.resolve())

    # Custom Claude project directory, if configured.
    custom_name = os.environ.get("CLAUDE_CODE_PROJECT_DIR_NAME")
    if custom_name and os.environ.get("CLAUDE_CONFIG_DIR"):
        candidate = projects_root / custom_name
        if candidate.exists():
            result.add(candidate.resolve())

    # Best-effort discovery:
    # catches Claude sessions started from a subdirectory of the repository,
    # very long paths, etc.
    try:
        for directory in projects_root.iterdir():
            if not directory.is_dir():
                continue

            if directory.resolve() in result:
                continue

            session_files = list(directory.glob("*.jsonl"))

            for transcript in session_files[:5]:
                cwd = get_cwd_from_transcript(transcript)
                if not cwd:
                    continue

                try:
                    cwd_path = Path(cwd)
                    if path_inside(cwd_path, repo):
                        result.add(directory.resolve())
                        break
                except Exception:
                    continue
    except Exception:
        pass

    return sorted(result)


def files_equal(a: Path, b: Path) -> bool:
    try:
        return (
            a.stat().st_size == b.stat().st_size
            and filecmp.cmp(a, b, shallow=False)
        )
    except Exception:
        return False


def is_prefix(shorter: Path, longer: Path) -> bool:
    try:
        short_size = shorter.stat().st_size
        long_size = longer.stat().st_size

        if short_size > long_size:
            return False

        remaining = short_size

        with shorter.open("rb") as sf, longer.open("rb") as lf:
            while remaining > 0:
                chunk_size = min(1024 * 1024, remaining)

                a = sf.read(chunk_size)
                b = lf.read(chunk_size)

                if a != b:
                    return False

                remaining -= len(a)

                if not a:
                    break

        return remaining == 0

    except Exception:
        return False


def conflict_path(conflicts_dir: Path, src: Path) -> Path:
    host = re.sub(r"[^A-Za-z0-9_-]", "_", socket.gethostname())
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return conflicts_dir / f"{src.stem}.{host}.{stamp}.jsonl"


def safe_merge(src: Path, dst: Path, conflicts_dir: Path):
    """
    Session transcripts are normally append-like.

    Cases:
      src == dst              -> nothing
      dst is prefix of src    -> source is newer, replace archive
      src is prefix of dst    -> archive is newer, keep archive
      neither                 -> conflict, never overwrite silently
    """

    if src.resolve() == dst.resolve():
        return "same"

    if not dst.exists():
        shutil.copy2(src, dst)
        return "added"

    if files_equal(src, dst):
        return "same"

    if is_prefix(dst, src):
        shutil.copy2(src, dst)
        return "updated"

    if is_prefix(src, dst):
        return "archive-newer"

    conflict = conflict_path(conflicts_dir, src)
    shutil.copy2(src, conflict)

    print(
        f"[CONFLICT] {src.name}\n"
        f"  local:   {src}\n"
        f"  archive: {dst}\n"
        f"  saved:   {conflict}",
        file=sys.stderr,
    )

    return "conflict"


def load_manifest(path: Path):
    if not path.exists():
        return {"version": 1, "latest_id": None, "sessions": {}}

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        data.setdefault("version", 1)
        data.setdefault("latest_id", None)
        data.setdefault("sessions", {})

        return data
    except Exception:
        return {"version": 1, "latest_id": None, "sessions": {}}


def save_manifest(path: Path, data):
    data["updated_at"] = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    temp = path.with_suffix(".tmp")

    with temp.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    temp.replace(path)


def index_local_sessions():
    projects_root = get_projects_root()
    result = {}

    if not projects_root.exists():
        return result

    try:
        for project_dir in projects_root.iterdir():
            if not project_dir.is_dir():
                continue

            for transcript in project_dir.glob("*.jsonl"):
                result.setdefault(transcript.stem, []).append(transcript)
    except Exception:
        pass

    return result


def first_user_message(path: Path):
    """
    Cosmetic / best-effort preview only.
    The sync mechanism does NOT depend on this parser.
    """
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i > 300:
                    break

                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                if obj.get("type") != "user":
                    continue

                msg = obj.get("message", {})
                content = msg.get("content")

                texts = []

                if isinstance(content, str):
                    texts.append(content)

                elif isinstance(content, list):
                    for block in content:
                        if (
                            isinstance(block, dict)
                            and block.get("type") == "text"
                            and isinstance(block.get("text"), str)
                        ):
                            texts.append(block["text"])

                text = " ".join(texts).strip()

                if not text:
                    continue

                if text.startswith("<"):
                    continue

                text = re.sub(r"\s+", " ", text)

                if len(text) > 100:
                    text = text[:97] + "..."

                return text

    except Exception:
        pass

    return ""


def capture(repo: Path, quiet=False):
    archive, sessions_dir, conflicts_dir, manifest_path = get_archive_paths(repo)

    manifest = load_manifest(manifest_path)
    session_meta = manifest["sessions"]

    sources = set()

    # Sessions belonging to the current repository.
    project_dirs = find_project_session_dirs(repo)

    for project_dir in project_dirs:
        for path in project_dir.glob("*.jsonl"):
            sources.add(path.resolve())

    # Also look for local copies of sessions already in the archive.
    # This is important after resuming the portable transcript on another OS.
    local_index = index_local_sessions()

    for archived in sessions_dir.glob("*.jsonl"):
        sid = archived.stem

        for candidate in local_index.get(sid, []):
            sources.add(candidate.resolve())

    changed = 0

    for src in sorted(sources):
        sid = src.stem
        dst = sessions_dir / f"{sid}.jsonl"

        status = safe_merge(src, dst, conflicts_dir)

        if status in {"added", "updated"}:
            changed += 1

        meta = session_meta.setdefault(sid, {})

        try:
            activity_ns = src.stat().st_mtime_ns
        except Exception:
            activity_ns = 0

        meta["file"] = f"sessions/{sid}.jsonl"
        meta["activity_ns"] = max(
            int(meta.get("activity_ns", 0)),
            int(activity_ns),
        )

        if dst.exists():
            meta["size"] = dst.stat().st_size

    # Discover archive files missing from manifest.
    for archived in sessions_dir.glob("*.jsonl"):
        sid = archived.stem

        meta = session_meta.setdefault(sid, {})

        meta["file"] = f"sessions/{sid}.jsonl"
        meta["size"] = archived.stat().st_size

        if not meta.get("activity_ns"):
            meta["activity_ns"] = archived.stat().st_mtime_ns

    if session_meta:
        latest_id = max(
            session_meta,
            key=lambda sid: int(
                session_meta[sid].get("activity_ns", 0)
            ),
        )

        manifest["latest_id"] = latest_id

    save_manifest(manifest_path, manifest)

    if not quiet:
        print()
        print(f"Repository : {repo}")
        print(f"Claude dir : {get_claude_home()}")
        print(f"Archive    : {archive}")
        print(f"Sessions   : {len(session_meta)}")
        print(f"Changed    : {changed}")

        if manifest.get("latest_id"):
            print(f"Latest     : {manifest['latest_id']}")

    return manifest


def list_sessions(repo: Path):
    _, sessions_dir, _, manifest_path = get_archive_paths(repo)

    manifest = load_manifest(manifest_path)

    entries = []

    for sid, meta in manifest.get("sessions", {}).items():
        path = sessions_dir / f"{sid}.jsonl"

        if not path.exists():
            continue

        entries.append(
            (
                int(meta.get("activity_ns", 0)),
                sid,
                path,
                meta,
            )
        )

    entries.sort(reverse=True)

    if not entries:
        print("No archived Claude sessions.")
        return

    latest = manifest.get("latest_id")

    for activity_ns, sid, path, meta in entries:
        marker = "*" if sid == latest else " "

        try:
            date = datetime.fromtimestamp(
                activity_ns / 1_000_000_000
            ).astimezone().strftime("%Y-%m-%d %H:%M")
        except Exception:
            date = "?"

        preview = first_user_message(path)

        print(
            f"{marker} {date}  "
            f"{sid}  "
            f"{meta.get('size', path.stat().st_size):>10} bytes"
        )

        if preview:
            print(f"    {preview}")


def search_sessions(repo: Path, query: str):
    _, sessions_dir, _, _ = get_archive_paths(repo)

    q = query.lower()
    matches = []

    for path in sessions_dir.glob("*.jsonl"):
        try:
            text = path.read_text(
                encoding="utf-8",
                errors="ignore",
            ).lower()

            if q in text:
                matches.append(path)

        except Exception:
            continue

    if not matches:
        print(f'No session contains "{query}".')
        return

    print(f'Matches for "{query}":')

    for path in matches:
        preview = first_user_message(path)
        print(f"  {path.stem}")

        if preview:
            print(f"    {preview}")


def resolve_session(repo: Path, target: str):
    _, sessions_dir, _, manifest_path = get_archive_paths(repo)

    manifest = load_manifest(manifest_path)

    if target == "latest":
        sid = manifest.get("latest_id")

        if not sid:
            raise RuntimeError("No latest session in manifest.")

        path = sessions_dir / f"{sid}.jsonl"

        if not path.exists():
            raise RuntimeError(
                f"Latest session file does not exist: {path}"
            )

        return sid, path

    exact = sessions_dir / f"{target}.jsonl"

    if exact.exists():
        return target, exact

    matches = [
        path
        for path in sessions_dir.glob("*.jsonl")
        if path.stem.startswith(target)
    ]

    if len(matches) == 1:
        return matches[0].stem, matches[0]

    if len(matches) > 1:
        raise RuntimeError(
            f'Session prefix "{target}" is ambiguous.'
        )

    raise RuntimeError(
        f'Session "{target}" not found in {sessions_dir}'
    )


def resume_session(repo: Path, target: str):
    # Collect anything currently present locally first.
    capture(repo, quiet=True)

    sid, transcript = resolve_session(repo, target)

    claude = shutil.which("claude")

    if not claude:
        raise RuntimeError(
            "Claude Code executable was not found in PATH."
        )

    before_mtime = transcript.stat().st_mtime_ns

    print()
    print(f"Resuming session:")
    print(f"  id         : {sid}")
    print(f"  transcript : {transcript.resolve()}")
    print(f"  cwd        : {repo}")
    print()

    result = subprocess.run(
        [
            claude,
            "--resume",
            str(transcript.resolve()),
        ],
        cwd=str(repo),
    )

    # After Claude exits, collect any local transcript copy.
    manifest = capture(repo, quiet=True)

    try:
        after_mtime = transcript.stat().st_mtime_ns
    except Exception:
        after_mtime = before_mtime

    meta = manifest["sessions"].setdefault(sid, {})

    if after_mtime != before_mtime:
        meta["activity_ns"] = after_mtime
        meta["size"] = transcript.stat().st_size

    # The explicitly resumed session should be the next "latest".
    manifest["latest_id"] = sid

    _, _, _, manifest_path = get_archive_paths(repo)
    save_manifest(manifest_path, manifest)

    print()
    print("Claude session finished.")
    print()
    print("Portable transcript has been collected.")
    print("You can now run:")
    print()
    print("  git status")
    print(f"  git add {ARCHIVE_NAME}")
    print()

    return result.returncode


def show_paths(repo: Path):
    archive, sessions, conflicts, manifest = get_archive_paths(repo)

    print(f"Repository      : {repo}")
    print(f"Claude home     : {get_claude_home()}")
    print(f"Claude projects : {get_projects_root()}")
    print(f"Archive         : {archive}")
    print(f"Sessions        : {sessions}")
    print(f"Conflicts       : {conflicts}")
    print(f"Manifest        : {manifest}")

    dirs = find_project_session_dirs(repo)

    print()
    print("Detected local Claude project directories:")

    if not dirs:
        print("  <none>")
    else:
        for d in dirs:
            print(f"  {d}")


def main():
    parser = argparse.ArgumentParser(
        description="Portable Claude Code session sync"
    )

    commands = parser.add_subparsers(dest="command")

    commands.add_parser(
        "capture",
        help="Collect local Claude sessions into .claude-sync",
    )

    commands.add_parser(
        "list",
        help="List archived sessions",
    )

    search_parser = commands.add_parser(
        "search",
        help="Search archived transcripts",
    )
    search_parser.add_argument("query")

    resume_parser = commands.add_parser(
        "resume",
        help="Resume an archived Claude Code session",
    )
    resume_parser.add_argument(
        "session",
        nargs="?",
        default="latest",
        help='Session ID/prefix, or "latest"',
    )

    commands.add_parser(
        "where",
        help="Show detected Claude/session paths",
    )

    args = parser.parse_args()

    repo = get_repo_root()

    try:
        if args.command == "capture":
            capture(repo)

        elif args.command == "list":
            list_sessions(repo)

        elif args.command == "search":
            search_sessions(repo, args.query)

        elif args.command == "resume":
            sys.exit(
                resume_session(repo, args.session)
            )

        elif args.command == "where":
            show_paths(repo)

        else:
            parser.print_help()

    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()