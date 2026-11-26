{
  name = "tarako-real-hardware-export-policy";

  testScript = ''
    from datetime import timedelta

    candidate = driver.out_dir / "candidate.json"
    if candidate.exists():
        raise SystemExit("Use a fresh --output_directory; refusing to overwrite candidate.json.")

    start_all()
    attester.wait_for_unit("multi-user.target", timeout=timedelta(minutes=2))
    attester.succeed("systemctl start tarako-tdx-prepare-attester.service")
    policy = attester.succeed("tarako-tdx-candidate-policy /mnt/tarako-live-tdx/attester")
    with candidate.open("x") as file:
        file.write(policy)
    print(f"Wrote unreviewed candidate to {candidate}; no attestation test ran.", flush=True)
  '';
}
