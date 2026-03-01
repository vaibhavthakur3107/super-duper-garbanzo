"""
Real-time Process Management System
Live command control and monitoring for security tool execution.
Inspired by hexstrike-ai and pentagi process management.
"""

import enum
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


class ProcessStatus(enum.Enum):
    """Lifecycle status of a managed process."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"


@dataclass
class ProcessInfo:
    """Snapshot of a managed subprocess."""

    pid: int
    command: str
    status: ProcessStatus = ProcessStatus.RUNNING
    start_time: float = field(default_factory=time.time)
    output: str = ""
    exit_code: Optional[int] = None


class ProcessManager:
    """
    Manages the lifecycle of security-tool subprocesses.

    Provides start / stop / inspect operations with automatic output
    collection and optional per-process timeouts.
    """

    def __init__(self):
        self._processes: dict[int, ProcessInfo] = {}
        self._subprocesses: dict[int, subprocess.Popen] = {}
        self._lock = threading.Lock()
        self._history: list[ProcessInfo] = []

    # ── Public API ───────────────────────────────────────────────────────────

    def start_process(self, command: str, timeout: int = 300) -> ProcessInfo:
        """
        Launch *command* in a subprocess and return its :class:`ProcessInfo`.

        Output is collected asynchronously in a background thread.
        If the process exceeds *timeout* seconds it is terminated and marked
        ``TIMEOUT``.
        """
        args = shlex.split(command)
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        info = ProcessInfo(pid=proc.pid, command=command)

        with self._lock:
            self._processes[proc.pid] = info
            self._subprocesses[proc.pid] = proc

        # Background reader
        reader = threading.Thread(
            target=self._collect_output,
            args=(proc, info, timeout),
            daemon=True,
        )
        reader.start()

        return info

    def stop_process(self, pid: int) -> bool:
        """Terminate the process identified by *pid*.  Returns ``True`` on success."""
        with self._lock:
            proc = self._subprocesses.get(pid)
            info = self._processes.get(pid)

        if proc is None or info is None:
            return False

        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

        with self._lock:
            info.status = ProcessStatus.KILLED
            info.exit_code = proc.returncode
        return True

    def get_process(self, pid: int) -> Optional[ProcessInfo]:
        """Return :class:`ProcessInfo` for *pid*, or ``None``."""
        with self._lock:
            return self._processes.get(pid)

    def list_processes(self, status: Optional[ProcessStatus] = None) -> list[ProcessInfo]:
        """Return all tracked processes, optionally filtered by *status*."""
        with self._lock:
            procs = list(self._processes.values())
        if status is not None:
            procs = [p for p in procs if p.status == status]
        return procs

    def get_output(self, pid: int) -> str:
        """Return captured stdout/stderr for *pid*."""
        with self._lock:
            info = self._processes.get(pid)
        return info.output if info else ""

    def cleanup_finished(self) -> int:
        """
        Move completed / failed / killed processes to history.

        Returns the number of processes cleaned up.
        """
        cleaned = 0
        with self._lock:
            finished_pids = [
                pid
                for pid, info in self._processes.items()
                if info.status != ProcessStatus.RUNNING
            ]
            for pid in finished_pids:
                info = self._processes.pop(pid)
                self._subprocesses.pop(pid, None)
                self._history.append(info)
                cleaned += 1
        return cleaned

    def get_stats(self) -> dict:
        """Return aggregate process statistics."""
        with self._lock:
            all_procs = list(self._processes.values()) + self._history
        return {
            "total": len(all_procs),
            "running": sum(1 for p in all_procs if p.status == ProcessStatus.RUNNING),
            "completed": sum(1 for p in all_procs if p.status == ProcessStatus.COMPLETED),
            "failed": sum(
                1
                for p in all_procs
                if p.status in (ProcessStatus.FAILED, ProcessStatus.TIMEOUT, ProcessStatus.KILLED)
            ),
        }

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _collect_output(
        self,
        proc: subprocess.Popen,
        info: ProcessInfo,
        timeout: int,
    ) -> None:
        """Read subprocess output in a background thread with timeout."""
        try:
            stdout, _ = proc.communicate(timeout=timeout)
            with self._lock:
                info.output = stdout or ""
                info.exit_code = proc.returncode
                info.status = (
                    ProcessStatus.COMPLETED if proc.returncode == 0 else ProcessStatus.FAILED
                )
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
            with self._lock:
                info.output = stdout or ""
                info.exit_code = proc.returncode
                info.status = ProcessStatus.TIMEOUT


# Module-level default instance
process_manager = ProcessManager()
