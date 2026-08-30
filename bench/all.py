import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.backends import ROOT, add_output_argument, directory_named, shown


class Stage:

    def __init__(self, name: str, script: str, arguments: list[str], writes: str | None,
                 note: str, takes: str):
        self.name = name
        self.script = script
        self.arguments = arguments
        self.writes = writes
        self.note = note
        self.takes = takes

    def command(self, output_directory: Path) -> list[str]:
        command = [sys.executable, str(ROOT / self.script), *self.arguments]
        if self.writes is not None:
            command += ["--output-dir", str(output_directory)]
        return command


STAGES = (
    Stage("agreement", "bench/run.py",
          ["--record-count", "100", "--records-per-vehicle", "2", "--variant", "all"], None,
          "every backend agrees on every variant; a gate, not a measurement", "minutes"),
    Stage("crossover", "bench/crossover.py",
          ["--record-count", "5", "10", "20", "40", "80", "160"], "crossover.json",
          "figure 4: where the sorted form overtakes all-pairs", "tens of minutes"),
    Stage("decomposition", "bench/decomposition.py", [], "decomposition.json",
          "figure 5: thirty configurations, twelve switches, each alone and in context",
          "two to three hours"),
    Stage("membership", "bench/membership.py", ["--record-count", "200"], "set-membership.json",
          "figure 6: the three shapes of P3's membership gadget against |S|",
          "an hour or two"),
    Stage("ceiling", "bench/ceiling.py", ["--memory-budget-gb", "16", "--timeout", "600"],
          "ceilings.json", "figures 7 and 8: the feasibility ceiling under a budget and a clock",
          "an hour or two"),
    Stage("verification", "bench/verification.py",
          ["--record-count", "10", "40", "100", "200", "400"], "verification-cost.json",
          "what a verifier pays, against what a prover pays", "tens of minutes"),
    Stage("audit", "bench/audit.py", ["--record-count", "2000", "--parties", "5"],
          "audit-cost.json", "a third party auditing a completed round", "tens of minutes"),
    Stage("mpc", "mpc/witness.py", ["-M3", "--record-count", "20"], "mpc-binding.json",
          "the binding between the MPC opening and the proof; a witness, not a timing", "minutes"),
)

STAGE_NAMES = tuple(stage.name for stage in STAGES)


def toolchain() -> dict:

    def version(command: list[str]) -> str:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            return f"not readable: {error}"
        return (completed.stdout + completed.stderr).strip().splitlines()[0] if (
            completed.stdout or completed.stderr
        ) else "no output"

    def git(arguments: list[str]) -> str:
        try:
            completed = subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True,
                                       text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            return f"not readable: {error}"
        return completed.stdout.strip()

    dirty = git(["status", "--porcelain"])
    return {
        "cargo": version(["cargo", "--version"]),
        "nargo": version(["nargo", "--version"]),
        "bb": version(["bb", "--version"]),
        "python": sys.version.split()[0],
        "uv": version(["uv", "--version"]),
        "git_commit": git(["rev-parse", "HEAD"]),
        "git_branch": git(["rev-parse", "--abbrev-ref", "HEAD"]),
        "working_tree_is_dirty": bool(dirty),
        "modified_files": sorted(
            line.split(maxsplit=1)[1] for line in dirty.splitlines() if len(line.split()) > 1
        )
        if dirty
        else [],
    }


def run_stage(stage: Stage, output_directory: Path, timeout: float | None) -> dict:
    command = stage.command(output_directory)
    print(f"\n{'=' * 78}\n=== {stage.name}  ({stage.takes})\n=== {stage.note}\n"
          f"=== {' '.join(command[1:])}\n{'=' * 78}", flush=True)
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, cwd=ROOT, timeout=timeout)
        returncode = completed.returncode
        error = None
    except subprocess.TimeoutExpired:
        returncode = None
        error = f"exceeded the stage timeout of {timeout}s"
    except KeyboardInterrupt:
        raise
    except OSError as error_raised:
        returncode = None
        error = str(error_raised)
    seconds = time.perf_counter() - started

    written = None
    if stage.writes is not None:
        path = output_directory / stage.writes
        written = {"file": stage.writes, "exists": path.exists(),
                   "bytes": path.stat().st_size if path.exists() else 0}

    finding = {
        "stage": stage.name,
        "command": command[1:],
        "exit_status": returncode,
        "succeeded": returncode == 0,
        "wall_seconds": round(seconds, 1),
        "writes": written,
    }
    if error:
        finding["harness_error"] = error
    print(f"\n=== {stage.name}: "
          f"{'ok' if finding['succeeded'] else 'FAILED'} in {seconds / 60:.1f} min", flush=True)
    return finding


def main() -> None:
    parser = argparse.ArgumentParser(prog="bench/all.py")
    parser.add_argument(
        "--only", nargs="+", choices=STAGE_NAMES,
        help="run only these stages, in the order below rather than the order given",
    )
    parser.add_argument(
        "--skip", nargs="+", choices=STAGE_NAMES, default=[],
        help="run everything except these. `--skip ceiling ceiling-grid` is most of the day",
    )
    parser.add_argument(
        "--stage-timeout", type=float, default=None,
        help="seconds any one stage may take before it is abandoned and the run continues",
    )
    parser.add_argument("--list", action="store_true", help="print the stages and exit")
    add_output_argument(parser)
    arguments = parser.parse_args()

    if arguments.list:
        for stage in STAGES:
            writes = stage.writes or "(nothing; a gate)"
            print(f"  {stage.name:<14} {writes:<24} {stage.takes:<20} {stage.note}")
        return

    chosen = [
        stage for stage in STAGES
        if (arguments.only is None or stage.name in arguments.only)
        and stage.name not in arguments.skip
    ]
    output_directory = directory_named(arguments.output_dir)

    manifest = {
        "output_directory": str(shown(output_directory)),
        "toolchain": toolchain(),
        "order": [stage.name for stage in chosen],
        "stages": [],
    }
    manifest_path = output_directory / "manifest.json"

    def save() -> None:
        manifest_path.write_text(json.dumps(manifest, indent=1) + "\n")

    save()
    started = time.perf_counter()
    try:
        for stage in chosen:
            manifest["stages"].append(run_stage(stage, output_directory, arguments.stage_timeout))
            save()
    except KeyboardInterrupt:
        manifest["interrupted"] = True
        print("\ninterrupted; the stages that finished are in the manifest", flush=True)
    finally:
        manifest["wall_seconds_total"] = round(time.perf_counter() - started, 1)
        save()

    print(f"\n{'=' * 78}")
    for finding in manifest["stages"]:
        print(f"  {finding['stage']:<14} "
              f"{'ok    ' if finding['succeeded'] else 'FAILED'} "
              f"{finding['wall_seconds'] / 60:>7.1f} min  {finding['writes'] or ''}")
    total = manifest["wall_seconds_total"] / 3600
    failed = [f["stage"] for f in manifest["stages"] if not f["succeeded"]]
    print(f"\n  {total:.2f} hours, manifest in {shown(manifest_path)}")
    if failed:
        print(f"  FAILED: {', '.join(failed)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
