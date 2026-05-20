# Integration test: verify the signer kernel module depends on fsverity and IMA
# symbols. When those symbols are not exported by the kernel (because the config
# options are disabled), the module loader rejects the module with "Unknown
# symbol" errors.
#
# On this NixOS VM the default kernel already has CONFIG_FS_VERITY and
# CONFIG_IMA, so the module loads successfully — but we verify the
# dependency exists by inspecting the .ko symbol table directly.

import base64

start_all()

# Load signer — this succeeds on this kernel because the features are present.
# On a kernel without them, it would fail with "Unknown symbol".
machine.succeed("modprobe signer", timeout=30)
print("signer module loaded successfully")

# Get the module path (may end in .ko.xz)
ko = machine.succeed("modinfo -n signer").strip()
print("module path:", ko)

# Decompress and search for extern "C" symbol names in the .ko file
# using Python (available in the VM) via base64-encoded script.
script = b"""import lzma, sys
with lzma.open(sys.argv[1]) as f:
    data = f.read()
print(data.count(b'fsverity_get_digest'))
print(data.count(b'ima_measure_critical_data'))
"""
b64 = base64.b64encode(script).decode()
out = machine.succeed(f"echo {b64} | base64 -d | python3 - {ko}", timeout=30).strip().splitlines()
count_fsverity = int(out[0])
count_ima = int(out[1])

print(f"fsverity_get_digest references: {count_fsverity}")
print(f"ima_measure_critical_data references: {count_ima}")

assert count_fsverity > 0, "fsverity_get_digest not found in module symbols"
assert count_ima > 0, "ima_measure_critical_data not found in module symbols"

print("OK: signer module requires fsverity and IMA symbols — "
      "would be rejected on kernels without those features")
