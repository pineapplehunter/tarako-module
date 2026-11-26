"""Check that root cannot attach to the attester or read its process memory."""

import ctypes
import errno
import os
import sys

pid = int(sys.argv[1])
assert os.geteuid() == 0, "probe must run as root"
with open("/proc/self/status") as status:
    caps = next(line.split()[1] for line in status if line.startswith("CapEff:"))
assert int(caps, 16) & (1 << 19), "probe must have CAP_SYS_PTRACE"

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
PTRACE_ATTACH = 16
assert libc.ptrace(PTRACE_ATTACH, pid, None, None) == -1, "root PTRACE_ATTACH succeeded"
assert ctypes.get_errno() == errno.EPERM, "PTRACE_ATTACH failed for an unexpected reason"

try:
    with open("/proc/%d/mem" % pid, "rb"):
        pass
except PermissionError:
    pass
else:
    raise AssertionError("root could open Attester memory for reading")
