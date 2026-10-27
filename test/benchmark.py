# Quote latency benchmark for the standard and TDX NixOS VMs.
RUNS = 20
WARMUP = 2

attester.start(allow_reboot=not TDX)
attester.wait_for_unit("default.target")
attester.wait_until_succeeds("grep -q '^tarako ' /proc/modules", timeout=30)

# Enable fs-verity on the existing VM root filesystem. tune2fs can set this
# read-only-compatible feature while mounted; boot again so the kernel observes it.
root_device = attester.succeed("findmnt -n -o SOURCE /").strip()
attester.succeed(f"tune2fs -O verity {root_device}")
if TDX:
    # TDX CPUs cannot reset: start a new trust domain with the same disk.
    attester.shutdown()
    attester.start()
else:
    attester.reboot()
attester.wait_for_unit("default.target")
attester.wait_until_succeeds("grep -q '^tarako ' /proc/modules", timeout=30)

if TDX:
    with subtest("TDX quote benchmark"):
        attester.wait_until_succeeds(
            "test -e /dev/tdx_guest && "
            "test -d /sys/kernel/config/tsm/report",
            timeout=30,
        )
        tdx_result = attester.succeed(
            f"bench-tdx-quote --warmup {WARMUP} --runs {RUNS}"
        )
        print(tdx_result)
        assert "Benchmark: TDX quote" in tdx_result
        assert f"Runs:            {RUNS}" in tdx_result
        assert "Verification:    all quotes passed" in tdx_result
        assert "fresh random 32-byte value per invocation" in tdx_result

with subtest("Tarako quote benchmark"):
    tarako_result = attester.succeed(
        f"bench-tarako-quote --warmup {WARMUP} --runs {RUNS}"
    )
    print(tarako_result)
    assert "Benchmark: Tarako sign ioctl" in tarako_result
    assert f"Runs:            {RUNS}" in tarako_result

with subtest("TPM quote benchmark"):
    tpm_result = attester.succeed(
        f"bench-tpm-quote --warmup {WARMUP} --runs {RUNS}"
    )
    print(tpm_result)
    assert "Benchmark: TPM quote" in tpm_result
    assert f"Runs:            {RUNS}" in tpm_result
