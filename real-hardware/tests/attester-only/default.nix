{
  name = "tarako-real-hardware-attester-only";

  testScript = ''
    from datetime import timedelta
    import os
    import re
    from shlex import quote
    from urllib.request import urlopen

    output = driver.out_dir
    ca = output / "https-ca.pem"
    tls_name_file = output / "tls-name"
    if ca.exists() or tls_name_file.exists():
        raise SystemExit("Use a fresh --output_directory; refusing to overwrite attester files.")

    tls_name = os.environ.get("TARAKO_TDX_TLS_NAME", "attester")
    label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    if (len(tls_name) > 253 or not re.search(r"[A-Za-z]", tls_name)
            or not re.fullmatch(rf"{label}(?:\.{label})*", tls_name)):
        raise SystemExit("TARAKO_TDX_TLS_NAME must be a DNS hostname, not an IP or URL.")

    start_all()
    timeout = timedelta(seconds=30)
    attester.wait_for_unit("multi-user.target", timeout=timedelta(minutes=2))
    attester.succeed("systemctl start tarako-tdx-prepare-attester.service")
    state = "/run/tarako-live-tdx"
    attester.succeed(f"printf %s {quote(tls_name)} > {state}/tls-name")
    attester.succeed("systemctl start tarako-tdx-attester.service tarako-tdx-ima-log.service")
    attester.wait_for_open_port(8443, timeout=timeout)
    attester.wait_for_open_port(8080, timeout=timeout)
    with urlopen("http://127.0.0.1:8080/ima.log", timeout=5) as response:
        assert response.read(), "IMA log is empty through the host forward"
    with ca.open("x") as file:
        file.write(attester.succeed(f"cat {state}/ca.pem"))
    with tls_name_file.open("x") as file:
        file.write(tls_name + "\n")
    print(f"Attester ready on host loopback: HTTPS 8443 (TLS name {tls_name}), IMA 8080", flush=True)
    print(f"Wrote {ca.name} and {tls_name_file.name} to {output}. Press Ctrl-C to stop.", flush=True)
    attester.wait_for_shutdown()
  '';
}
