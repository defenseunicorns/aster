#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Opt-in real Docker context probe using only generated, credential-free files."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


# Independent fixture inventory, not derived by interpreting ignore patterns.
REQUIRED = {
    "Cargo.toml", "Cargo.lock", "LICENSE", "THIRD_PARTY_NOTICES.md",
    "lab/debian.sources", "tools/aster_path_delivery.py", "tools/aster_lan_mvp.py",
    "docker/path-lab/delivery-provision.py",
    "docker/path-lab/delivery-network-init.py",
    "docker/path-lab/delivery-agent.py", "docker/path-lab/delivery-wan.py",
}
for tree in ("crates", "proto", "third-party"):
    REQUIRED.update({f"{tree}/sentinel.txt", f"{tree}/nested/deep/sentinel.txt"})
DENIED = {
    ".env", ".git/config", "target/sentinel.txt", "unrelated/sentinel.txt",
    "lab/unrelated.txt", "lab/nested/sentinel.txt", "lab/.env",
    "tools/unrelated.py", "tools/nested/sentinel.txt", "tools/.env",
    "docker/unrelated.txt", "docker/other/sentinel.txt", "docker/.env",
    "docker/path-lab/unrelated.txt", "docker/path-lab/delivery-extra.py",
    "docker/path-lab/scenarios/sentinel.json", "docker/path-lab/.env",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="run a scratch BuildKit build")
    args = parser.parse_args()
    if not args.execute:
        print("NOT RUN: opt in with --execute (requires local Docker/BuildKit)")
        return 77
    docker = shutil.which("docker")
    if docker is None:
        print("NOT RUN: Docker CLI unavailable")
        return 77
    policy = Path(__file__).resolve().parents[1] / "docker/path-lab/Dockerfile.delivery.dockerignore"
    # Only this public policy is read from the repo. Never copy repository inputs,
    # user files, Docker config, credentials, or environment into the context.
    policy_text = policy.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="aster-context-probe-") as temporary:
        base = Path(temporary)
        context, output, config = (base / name for name in ("context", "output", "config"))
        context.mkdir()
        config.mkdir()
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(base),
               "DOCKER_CONFIG": str(config), "DOCKER_BUILDKIT": "1"}
        command = [docker, "--config", str(config), "--host", "unix:///var/run/docker.sock"]
        try:
            available = subprocess.run(command + ["info"], env=env, cwd=base,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            print("NOT RUN: local Docker availability check failed")
            return 77
        if available.returncode:
            print("NOT RUN: local Docker Engine unavailable")
            return 77
        for name in REQUIRED | DENIED:
            target = context / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("synthetic sentinel: " + name + "\n", encoding="utf-8")
        dockerfile = context / "docker/path-lab/Dockerfile.delivery"
        dockerfile.write_text("FROM scratch\nCOPY . /\n", encoding="utf-8")
        dockerfile.with_name(dockerfile.name + ".dockerignore").write_text(policy_text, encoding="utf-8")
        # Deliberately conflicting root policy proves sibling-policy precedence.
        (context / ".dockerignore").write_text("**\n", encoding="utf-8")
        try:
            build = subprocess.run(
                command + ["build", "--pull=false", "--no-cache", "--network=none",
                           "--file", "docker/path-lab/Dockerfile.delivery",
                           "--output", "type=local,dest=" + str(output), "."],
                env=env, cwd=context, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=120, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            print("FAIL: synthetic Docker build failed or timed out")
            return 1
        if build.returncode or not output.is_dir():
            print("FAIL: synthetic Docker build/export failed (BuildKit local exporter required)")
            return 1
        expected = set(REQUIRED)
        for name in REQUIRED:
            expected.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
        actual = {path.relative_to(output).as_posix() for path in output.rglob("*")}
        if actual != expected:
            print("FAIL: synthetic exported context differs; missing=" + repr(sorted(expected - actual))
                  + "; unexpected=" + repr(sorted(actual - expected)))
            return 1
        for name in REQUIRED:
            path = output / name
            if path.is_symlink() or not path.is_file() or path.read_text(encoding="utf-8") != "synthetic sentinel: " + name + "\n":
                print("FAIL: synthetic sentinel type/content differs")
                return 1
        print("PASS: real Docker exported exactly the synthetic required files and parents")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
