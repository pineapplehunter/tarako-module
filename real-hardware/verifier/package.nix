{
  lib,
  python3Packages,
  makeWrapper,
  dcap-verify,
}:

python3Packages.buildPythonApplication {
  pname = "tarako-tdx-verifier";
  version = "0.1.0";
  pyproject = true;
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./pyproject.toml
      ./tarako_tdx_verifier.py
      ./test_verifier.py
    ];
  };

  build-system = [ python3Packages.setuptools ];
  dependencies = [ python3Packages.cryptography ];
  nativeBuildInputs = [ makeWrapper ];

  makeWrapperArgs = [
    "--prefix"
    "PATH"
    ":"
    (lib.makeBinPath [ dcap-verify ])
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
