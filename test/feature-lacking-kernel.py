machine.succeed("modprobe signer", timeout=30)
print("signer module loaded successfully")

# Get the module path (may end in .ko.xz)
ko = machine.succeed("modinfo -n signer").strip()
print("module path:", ko)

# signer-app should fail on a kernel without fs-verity
out = machine.fail("signer-app 2>&1")
print(out)
print("signer-app failed as expected on a kernel without fs-verity")

