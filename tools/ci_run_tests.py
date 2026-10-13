"""Run the whole test suite for CI: verbose, and if it ever stalls, print where and stop instead of hanging.

Usage: python tools/ci_run_tests.py [seconds]   (default 600 seconds)
"""
import faulthandler
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    os.chdir(ROOT)
    sys.path.insert(0, ROOT)
    # If the suite takes longer than this, show the stack of every thread and exit with an error.
    faulthandler.dump_traceback_later(limit, exit=True)
    program = unittest.main(module=None, argv=["unittest", "discover", "-s", "tests", "-t", ".", "-v"], exit=False)
    sys.exit(0 if program.result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
