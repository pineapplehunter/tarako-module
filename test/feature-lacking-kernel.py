machine.succeed("modprobe tarako", timeout=30)
print("tarako module loaded successfully")

# Get the module path (may end in .ko.xz)
ko = machine.succeed("modinfo -n tarako").strip()
print("module path:", ko)

# tarako-app should fail on a kernel without fs-verity
out = machine.fail("tarako-app 2>&1")
print(out)
print("tarako-app failed as expected on a kernel without fs-verity")

