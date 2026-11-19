{
  lib,
  python3Packages,
  makeWrapper,
  dcapVerifier,
}:

python3Packages.buildPythonApplication {
  pname = "tarako-tdx-verifier";
  version = "0.1.0";
  pyproject = true;
  src = ./.;

  build-system = [ python3Packages.setuptools ];
  dependencies = [ python3Packages.cryptography ];
  nativeBuildInputs = [ makeWrapper ];

  makeWrapperArgs = [
    "--prefix"
    "PATH"
    ":"
    (lib.makeBinPath [ dcapVerifier ])
  ];

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    "$out/bin/tarako-tdx-verifier" --help
    python -m unittest -v
    runHook postInstallCheck
  '';

  meta.mainProgram = "tarako-tdx-verifier";
}
