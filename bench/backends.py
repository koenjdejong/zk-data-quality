import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import psutil
from shared.decomposition import command_flag

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIRECTORY = "results"

DEFAULT_POLL_SECONDS = 0.05


class GuardFailed(RuntimeError):
    pass


@dataclass
class GuardedResult:
    returncode: int
    stdout: str
    stderr: str
    killed: str | None
    elapsed_seconds: float
    peak_rss_bytes: int
    samples: int

    @property
    def peak_rss_gigabytes(self) -> float:
        return self.peak_rss_bytes / 1024**3


def _resident_set_of_tree(process: psutil.Process) -> int:
    total = 0
    try:
        total += process.memory_info().rss
        for child in process.children(recursive=True):
            try:
                total += child.memory_info().rss
            except psutil.Error:
                pass
    except psutil.Error:
        pass
    return total


def _kill_process_group(pid: int, deadline_seconds: float = 10.0) -> str | None:
    def gone() -> bool:
        try:
            return psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return True
        except psutil.Error:
            return False

    for signaller in (
        lambda: os.killpg(os.getpgid(pid), signal.SIGKILL),
        lambda: os.kill(pid, signal.SIGKILL),
    ):
        try:
            signaller()
        except ProcessLookupError:
            return None
        except PermissionError as refused:
            return f"not permitted to signal {pid}: {refused}"
        deadline = time.perf_counter() + deadline_seconds
        while time.perf_counter() < deadline:
            if gone():
                return None
            time.sleep(0.05)
    return f"process {pid} survived SIGKILL to its group and to itself"


def guarded_run(
    command: list[str],
    cwd: Path,
    memory_limit_bytes: int,
    timeout_seconds: float,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
) -> GuardedResult:
    stdout_file = tempfile.TemporaryFile()
    stderr_file = tempfile.TemporaryFile()

    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=stdout_file,
        stderr=stderr_file,
        start_new_session=True,
    )
    watched = psutil.Process(process.pid)

    peak = _resident_set_of_tree(watched)
    samples = 1
    killed = None
    kill_failure = None

    while process.poll() is None:
        resident = _resident_set_of_tree(watched)
        peak = max(peak, resident)
        samples += 1
        if resident > memory_limit_bytes:
            killed = "memory"
        elif time.perf_counter() - started > timeout_seconds:
            killed = "timeout"
        if killed:
            kill_failure = _kill_process_group(process.pid)
            break
        time.sleep(poll_seconds)

    process.wait()
    elapsed = time.perf_counter() - started

    stdout_file.seek(0)
    stderr_file.seek(0)
    stdout = stdout_file.read().decode(errors="replace")
    stderr = stderr_file.read().decode(errors="replace")
    stdout_file.close()
    stderr_file.close()

    if kill_failure is not None:
        raise GuardFailed(
            f"the guard decided to kill this run ({killed}) but could not: {kill_failure}"
        )

    return GuardedResult(
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        killed=killed,
        elapsed_seconds=elapsed,
        peak_rss_bytes=peak,
        samples=samples,
    )


def add_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIRECTORY,
        help="where to write this measurement's result file, relative to the repository root "
        "(absolute paths are taken as given). The filename does not change, so two directories are "
        f"directly comparable. Default: {DEFAULT_OUTPUT_DIRECTORY}",
    )


def results_directory(arguments) -> Path:
    return directory_named(getattr(arguments, "output_dir", DEFAULT_OUTPUT_DIRECTORY))


def directory_named(name: str | Path) -> Path:
    directory = Path(name)
    if not directory.is_absolute():
        directory = ROOT / directory
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def shown(path: Path) -> Path:
    return path.relative_to(ROOT) if path.is_relative_to(ROOT) else path


def write(arguments, filename: str, document) -> Path:
    import json

    output = results_directory(arguments) / filename
    output.write_text(json.dumps(document, indent=1) + "\n")
    print(f"\nwritten to {shown(output)}")
    return output

DEFAULT_MEMORY_BUDGET_BYTES = 16 * 1024**3
DEFAULT_TIMEOUT_SECONDS = 1800.0
RUST_BACKENDS = ("groth16", "nova")
BACKEND_NAMES = ("noir", "groth16", "nova")


FOLDING_BACKENDS = ("nova",)

MEMBERSHIP_GADGETS = ("or-chain", "product", "lookup")
DEFAULT_MEMBERSHIP_GADGET = "or-chain"
GADGET_SELECTING_BACKENDS = ("noir",)


def gadget_for(backend: str, requested: str | None) -> str | None:
    return requested if backend in GADGET_SELECTING_BACKENDS else None


class BackendError(RuntimeError):
    pass


def build_rust_backends() -> None:
    completed = subprocess.run(
        ["cargo", "build", "--release"], cwd=ROOT, capture_output=True, text=True
    )
    if completed.returncode != 0:
        raise BackendError(f"cargo build failed:\n{completed.stdout}{completed.stderr}")


def command_for(
    backend: str,
    dataset_path: Path,
    claimed_commitment: str | None = None,
    all_pairs: bool = False,
    enable: tuple[str, ...] | None = None,
    membership_gadget: str | None = None,
) -> list[str]:
    if backend == "noir":
        if claimed_commitment is not None:
            raise BackendError("noir returns its commitment as a public output, so it cannot be claimed")
        command = [sys.executable, str(ROOT / "noir" / "driver.py"), str(dataset_path)]
        if all_pairs:
            command.append("--all-pairs")
        if enable is not None:
            command.append(command_flag(enable))
        if membership_gadget is not None:
            command.append("--membership-gadget=" + membership_gadget)
        return command
    if backend in RUST_BACKENDS:
        if membership_gadget is not None:
            raise BackendError(
                f"{backend} implements the product-of-differences membership gadget only; the gadget "
                "shape is a Noir-side variable (see MEMBERSHIP_GADGETS). Route the request through "
                "gadget_for() rather than passing it down"
            )
        if all_pairs and backend in FOLDING_BACKENDS:
            raise BackendError(
                f"{backend} is a folding backend, and rung S2' needs a step circuit whose arity "
                "grows with the record count"
            )
        command = [str(ROOT / "target" / "release" / backend), str(dataset_path)]
        if claimed_commitment is not None:
            command.append(claimed_commitment)
        if all_pairs:
            command.append("--all-pairs")
        if enable is not None:
            command.append(command_flag(enable))
        return command
    raise BackendError(f"unknown backend {backend!r}")


def run_backend(
    backend: str,
    dataset_path: Path,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    claimed_commitment: str | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    all_pairs: bool = False,
    enable: tuple[str, ...] | None = None,
    membership_gadget: str | None = None,
) -> dict:
    outcome = probe_backend(
        backend,
        dataset_path,
        timeout=timeout,
        claimed_commitment=claimed_commitment,
        memory_budget_bytes=memory_budget_bytes,
        all_pairs=all_pairs,
        enable=enable,
        membership_gadget=membership_gadget,
    )
    if outcome["killed"]:
        raise BackendError(
            f"{backend} was killed by the guard ({outcome['killed']}) after "
            f"{outcome['elapsed_seconds']:.1f}s at {outcome['peak_rss_bytes'] / 1024**3:.2f} GB"
        )
    if "report" not in outcome:
        raise BackendError(outcome["error"])
    return outcome["report"]


def probe_backend(
    backend: str,
    dataset_path: Path,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    claimed_commitment: str | None = None,
    memory_budget_bytes: int = DEFAULT_MEMORY_BUDGET_BYTES,
    all_pairs: bool = False,
    enable: tuple[str, ...] | None = None,
    membership_gadget: str | None = None,
) -> dict:
    result = guarded_run(
        command_for(
            backend,
            dataset_path,
            claimed_commitment=claimed_commitment,
            all_pairs=all_pairs,
            enable=enable,
            membership_gadget=membership_gadget,
        ),
        cwd=ROOT,
        memory_limit_bytes=memory_budget_bytes,
        timeout_seconds=timeout,
    )
    outcome = {
        "backend": backend,
        "killed": result.killed,
        "elapsed_seconds": result.elapsed_seconds,
        "peak_rss_bytes": result.peak_rss_bytes,
        "guard_samples": result.samples,
    }
    if result.killed:
        return outcome

    reports = [line for line in result.stdout.splitlines() if line.strip().startswith("{")]
    if not reports:
        outcome["error"] = (
            f"{backend} printed no report (exit {result.returncode}):\n"
            f"{result.stdout}{result.stderr}"
        )
        return outcome

    report = json.loads(reports[-1])
    report["peak_rss_bytes"] = result.peak_rss_bytes
    report["guard_samples"] = result.samples
    report["elapsed_seconds"] = result.elapsed_seconds
    report["killed"] = None
    outcome["report"] = report
    return outcome
