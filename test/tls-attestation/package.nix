{ lib, python3Packages }:

python3Packages.buildPythonApplication {
  pname = "tarako-tls-mock";
  version = "0.1.0";
  pyproject = true;
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./pyproject.toml
      ./tarako_tls_mock
      ./test_services.py
    ];
  };

  build-system = [ python3Packages.setuptools ];
  dependencies = [ python3Packages.cryptography ];

  doCheck = true;
  checkPhase = ''
    runHook preCheck
    python -B -m unittest -v test_services
    runHook postCheck
  '';
}
