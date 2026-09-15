# INTENTIONALLY VULNERABLE test fixture - never deploy or copy.
# Planted: shell=True with user input (CWE-78), weak hash (CWE-327),
# and eval of untrusted text (CWE-94).

import hashlib
import subprocess
import sys


def archive(folder):
    # Flaw 1: argument reaches a shell.
    subprocess.call("tar -czf backup.tgz " + folder, shell=True)


def fingerprint(value):
    # Flaw 2: MD5 used where a secure hash is required.
    return hashlib.md5(value.encode()).hexdigest()


def apply_filter(expression, rows):
    # Flaw 3: untrusted expression evaluated as code.
    return [row for row in rows if eval(expression)]


if __name__ == "__main__":
    archive(sys.argv[1])
