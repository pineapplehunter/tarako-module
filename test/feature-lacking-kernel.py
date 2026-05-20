machine.succeed("modprobe signer", timeout=30)
print("signer module loaded successfully")

# Get the module path (may end in .ko.xz)
ko = machine.succeed("modinfo -n signer").strip()
print("module path:", ko)

