# Quote latency benchmark for the standard and TDX NixOS VMs.
import os

RUNS = 20
WARMUP = 2

attester.start()
attester.wait_for_unit("default.target")
attester.wait_until_succeeds("grep -q '^tarako ' /proc/modules", timeout=30)

nonce = os.urandom(32).hex()
print(f"Benchmark nonce: {nonce}")

if TDX:
    with subtest("TDX quote benchmark"):
        attester.wait_until_succeeds(
            "test -e /dev/tdx_guest && "
            "test -d /sys/kernel/config/tsm/report",
            timeout=30,
        )
        tdx_result = attester.succeed(
            f"bench-tdx-quote '{nonce}' --warmup {WARMUP} --runs {RUNS}"
        )
        print(tdx_result)
        assert "Benchmark: TDX quote" in tdx_result
        assert f"Runs:            {RUNS}" in tdx_result

with subtest("Tarako quote benchmark"):
    tarako_result = attester.succeed(
        f"bench-tarako-quote '{nonce}' --warmup {WARMUP} --runs {RUNS}"
    )
    print(tarako_result)
    assert "Benchmark: Tarako sign ioctl" in tarako_result
    assert f"Runs:            {RUNS}" in tarako_result

with subtest("TPM quote benchmark"):
    tpm_result = attester.succeed(
        f"bench-tpm-quote '{nonce}' --warmup {WARMUP} --runs {RUNS}"
    )
    print(tpm_result)
    assert "Benchmark: TPM quote" in tpm_result
    assert f"Runs:            {RUNS}" in tpm_result
