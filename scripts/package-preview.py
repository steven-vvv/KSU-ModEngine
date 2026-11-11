"""Package the native developer preview; never produce a KernelSU module ZIP."""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.1.0"
name = f"ksu-modengine-{VERSION}-linux-{platform.machine()}-preview"
dist = ROOT / "dist"
stage = dist / name
if stage.exists():
    shutil.rmtree(stage)
(stage / "bin").mkdir(parents=True)
for binary in ("ksu-mod-hostd", "runner-lua54", "runner-qjs"):
    shutil.copy2(ROOT / "target/release" / binary, stage / "bin" / binary)
for directory in ("examples", "docs"):
    shutil.copytree(ROOT / directory, stage / directory)
shutil.copytree(ROOT / "webui/dist", stage / "webui")
shutil.copy2(ROOT / "README.md", stage / "README.md")
shutil.copy2(ROOT / "Cargo.lock", stage / "Cargo.lock")
shutil.copy2(ROOT / "webui/pnpm-lock.yaml", stage / "pnpm-lock.yaml")
manifest = {
    "version": VERSION,
    "platform": f"linux-{platform.machine()}",
    "kind": "developer-preview",
    "android_module": False,
    "default_sandbox": "strict",
    "fixture_only": True,
    "quick_start": "bin/ksu-mod-hostd doctor --json",
}
(stage / "preview.json").write_text(
    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
)
checksums = []
for path in sorted(stage.rglob("*")):
    if path.is_file():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksums.append(f"{digest}  {path.relative_to(stage).as_posix()}\n")
(stage / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
archive = dist / f"{name}.tar.gz"
with tarfile.open(archive, "w:gz") as output:
    output.add(stage, arcname=name)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
Path(str(archive) + ".sha256").write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
print(archive)
