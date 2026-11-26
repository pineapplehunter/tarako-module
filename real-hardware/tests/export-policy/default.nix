{
  name = "tarako-real-hardware-export-policy";

  testScript = ''
    candidate = driver.out_dir / "candidate.json"
    if candidate.exists():
        raise SystemExit("Use a fresh --output_directory; refusing to overwrite candidate.json.")

    start_all()

    with subtest("prepare the measured attester executable"):
        attester.succeed("systemctl start tarako-tdx-prepare-attester.service")

    with subtest("export the candidate policy"):
        policy = attester.succeed("tarako-tdx-candidate-policy /mnt/tarako-live-tdx/attester")
        with candidate.open("x") as file:
            file.write(policy)
        print(f"Wrote unreviewed candidate to {candidate}; no attestation test ran.", flush=True)
  '';
}
