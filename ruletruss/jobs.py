"""Background imports. A big capture can take many minutes, so the browser starts the import, then asks how it is going.

Jobs live in memory only (they end with the server). Each job runs one analysis in a thread of the server; the analysis itself still runs
in the separate resource-limited worker process, which a cancel stops.
"""
import secrets
import threading
import time

from . import isolate

MAX_RUNNING = 2
KEEP_FINISHED = 40


class Job:
    def __init__(self, project_id, filename):
        self.id = secrets.token_hex(8)
        self.project_id, self.filename = project_id, filename
        self.state, self.message, self.entry = "running", "", None
        self.started, self.finished = time.time(), None
        self.progress_path, self.proc = None, None
        self._cancel = threading.Event()

    # called by the analysis
    def on_start(self, proc, progress_path):
        self.proc, self.progress_path = proc, progress_path

    def is_cancelled(self):
        return self._cancel.is_set()

    def view(self):
        progress = isolate.read_progress(self.progress_path) if self.progress_path and self.state == "running" else None
        if progress and progress["total"] > 0:
            progress["percent"] = min(99, int(100 * progress["bytes"] / progress["total"]))
        end = self.finished or time.time()
        return {"id": self.id, "project_id": self.project_id, "filename": self.filename, "state": self.state, "message": self.message,
                "elapsed_seconds": int(end - self.started), "progress": progress, "entry": self.entry}


class Jobs:
    def __init__(self):
        self._lock = threading.Lock()
        self._jobs = {}

    def running(self):
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.state == "running")

    def has_room(self):
        return self.running() < MAX_RUNNING

    def start(self, project_id, filename, work):
        """Run work(job) in a thread; its return value becomes job.entry. Raises RuntimeError if too many are running."""
        job = Job(project_id, filename)
        with self._lock:
            if sum(1 for j in self._jobs.values() if j.state == "running") >= MAX_RUNNING:
                raise RuntimeError("too many imports are running")
            self._jobs[job.id] = job
            finished = [j for j in self._jobs.values() if j.state != "running"]
            for old in sorted(finished, key=lambda j: j.finished or 0)[:max(0, len(finished) - KEEP_FINISHED)]:
                del self._jobs[old.id]

        def run():
            try:
                job.entry = work(job)
                state, message = "done", ""
            except isolate.Cancelled:
                state, message = "cancelled", "stopped"
            except ValueError as error:                  # ApiError and ParseFailure carry messages that are safe to show
                state, message = "error", str(error)[:500]
            except Exception:
                state, message = "error", "the file could not be processed"
            with self._lock:
                job.state, job.message, job.finished = state, message, time.time()

        threading.Thread(target=run, daemon=True, name=f"import-{job.id}").start()
        return job

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id):
        job = self.get(job_id)
        if job is not None and job.state == "running":
            job._cancel.set()
        return job
