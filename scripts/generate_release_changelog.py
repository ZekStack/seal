#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path


def run_git(args):
    return subprocess.check_output(["git", *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-ref", required=True)
    parser.add_argument("--tag-name", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        previous = run_git(["describe", "--tags", "--abbrev=0", f"{args.target_ref}^"])
        log_range = f"{previous}..{args.target_ref}"
    except subprocess.CalledProcessError:
        previous = ""
        log_range = args.target_ref

    lines = [f"# Seal {args.tag_name}", ""]
    if previous:
        lines.append(f"Changes since `{previous}`.")
        lines.append("")

    try:
        commits = run_git(["log", "--pretty=format:- %s", log_range])
    except subprocess.CalledProcessError:
        commits = ""
    lines.append(commits if commits else "- Initial release.")
    lines.append("")

    Path(args.output).write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
