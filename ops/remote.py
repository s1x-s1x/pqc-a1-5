"""Sync the development mirror and run commands in the server workspace."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import stat
import sys
import time

import paramiko


LOCAL_ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = PurePosixPath("/home/guest-experiment/pqc-a1-5")
EXCLUDED = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "build"}


def connect():
    jump = paramiko.SSHClient()
    jump.load_system_host_keys()
    jump.connect(
        os.environ["A15_JUMP_HOST"], username=os.environ["A15_JUMP_USER"],
        password=os.environ["A15_JUMP_PASSWORD"],
        timeout=30, auth_timeout=30, look_for_keys=False, allow_agent=False,
    )
    channel = jump.get_transport().open_channel(
        "direct-tcpip", (os.environ["A15_TARGET_HOST"], 22), ("127.0.0.1", 0),
    )
    remote = paramiko.SSHClient()
    remote.load_system_host_keys()
    remote.connect(
        os.environ["A15_TARGET_HOST"], username=os.environ["A15_TARGET_USER"],
        password=os.environ["A15_TARGET_PASSWORD"], sock=channel,
        timeout=30, auth_timeout=30, look_for_keys=False, allow_agent=False,
    )
    remote.get_transport().set_keepalive(20)
    return jump, remote


def mkdir(sftp, path):
    try:
        info = sftp.lstat(str(path))
        import stat
        if not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f"Expected directory: {path}")
    except FileNotFoundError:
        mkdir(sftp, path.parent)
        sftp.mkdir(str(path))


def sync(remote, paths):
    with remote.open_sftp() as sftp:
        mkdir(sftp, REMOTE_ROOT)
        count = 0
        for relative in paths or ["."]:
            source = (LOCAL_ROOT / relative).resolve()
            if not source.is_relative_to(LOCAL_ROOT):
                raise ValueError("Sync path must be inside the development mirror")
            files = source.rglob("*") if source.is_dir() else [source]
            for local in files:
                rel = local.relative_to(LOCAL_ROOT)
                if not local.is_file() or any(part in EXCLUDED for part in rel.parts):
                    continue
                destination = REMOTE_ROOT.joinpath(*rel.parts)
                mkdir(sftp, destination.parent)
                temporary = str(destination) + ".upload-" + str(os.getpid())
                sftp.put(str(local), temporary)
                sftp.posix_rename(temporary, str(destination))
                count += 1
        print(json.dumps({"remote_root": str(REMOTE_ROOT), "uploaded_files": count}))


def pull(remote, paths):
    """Copy project evidence back without traversing links or escaping either root."""
    def safe_relative(value):
        relative = PurePosixPath(value.replace("\\", "/"))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Pull path must be relative to the server project")
        return relative

    count = 0
    with remote.open_sftp() as sftp:
        def copy(relative):
            nonlocal count
            source = REMOTE_ROOT / relative
            info = sftp.lstat(str(source))
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f"Pull does not follow symbolic links: {relative}")
            if stat.S_ISDIR(info.st_mode):
                for entry in sorted(sftp.listdir_attr(str(source)), key=lambda item: item.filename):
                    if entry.filename not in EXCLUDED:
                        copy(relative / entry.filename)
            elif stat.S_ISREG(info.st_mode):
                destination = LOCAL_ROOT.joinpath(*relative.parts).resolve()
                if not destination.is_relative_to(LOCAL_ROOT):
                    raise ValueError("Pull destination must stay inside the development mirror")
                destination.parent.mkdir(parents=True, exist_ok=True)
                temporary = destination.with_name(destination.name + ".download-" + str(os.getpid()))
                sftp.get(str(source), str(temporary))
                os.replace(temporary, destination)
                count += 1
        for value in paths:
            copy(safe_relative(value))
    print(json.dumps({"remote_root": str(REMOTE_ROOT), "downloaded_files": count}))


def run(remote, command, cwd, timeout):
    if cwd:
        directory = REMOTE_ROOT / cwd
        command = "cd " + shlex.quote(str(directory)) + " && " + command
    channel = remote.get_transport().open_session()
    channel.exec_command(command)
    started = time.monotonic()
    while True:
        if channel.recv_ready():
            sys.stdout.write(channel.recv(65536).decode("utf-8", errors="replace"))
            sys.stdout.flush()
        if channel.recv_stderr_ready():
            sys.stderr.write(channel.recv_stderr(65536).decode("utf-8", errors="replace"))
            sys.stderr.flush()
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        if time.monotonic() - started > timeout:
            channel.close()
            raise TimeoutError(f"Remote command exceeded {timeout} seconds")
        time.sleep(0.05)
    return channel.recv_exit_status()


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    upload = subparsers.add_parser("sync")
    upload.add_argument("paths", nargs="*")
    download = subparsers.add_parser("pull")
    download.add_argument("paths", nargs="+")
    execute = subparsers.add_parser("run")
    execute.add_argument("--cwd", default=".")
    execute.add_argument("--timeout", type=int, default=3600)
    execute.add_argument("command")
    args = parser.parse_args()
    jump, remote = connect()
    try:
        if args.action == "sync":
            sync(remote, args.paths)
            return 0
        if args.action == "pull":
            pull(remote, args.paths)
            return 0
        return run(remote, args.command, args.cwd, args.timeout)
    finally:
        remote.close()
        jump.close()


if __name__ == "__main__":
    raise SystemExit(main())
