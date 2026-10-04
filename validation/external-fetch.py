"""Pull only this agent's external evidence from the fixed server workspace."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ops.remote import connect, REMOTE_ROOT


def files(sftp, relative):
    path = REMOTE_ROOT / relative
    for item in sftp.listdir_attr(str(path)):
        child = relative / item.filename
        if stat.S_ISDIR(item.st_mode):
            yield from files(sftp, child)
        elif stat.S_ISREG(item.st_mode):
            yield child


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--artifacts-only", action="store_true")
args = parser.parse_args()
jump, remote = connect()
try:
    with remote.open_sftp() as sftp:
        paths = [] if args.artifacts_only else list(files(sftp, PurePosixPath("third_party/external_vectors")))
        for directory in ("vectors", "validation"):
            for item in sftp.listdir_attr(str(REMOTE_ROOT / directory)):
                if item.filename.startswith("external") and stat.S_ISREG(item.st_mode):
                    paths.append(PurePosixPath(directory) / item.filename)
        for relative in paths:
            destination = ROOT.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = str(destination) + ".download-" + str(os.getpid())
            sftp.get(str(REMOTE_ROOT / relative), temporary)
            os.replace(temporary, destination)
        print(json.dumps({"downloaded_files": len(paths)}))
finally:
    remote.close()
    jump.close()
