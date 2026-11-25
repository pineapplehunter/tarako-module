{
  lib,
  buildGoModule,
  fetchFromGitHub,
}:
buildGoModule {
  pname = "tdx-verify";
  version = "0-unstable-2026-10-14";

  src = fetchFromGitHub {
    owner = "google";
    repo = "go-tdx-guest";
    rev = "23b3eac9db39ba4e1df1426bacb3bfa3a7018e97";
    hash = "sha256-3OO1bYDF6rQGe34kUBMSgsQaoKy4XI4Nk5eudxoqZoo=";
  };
  vendorHash = "sha256-adb439sXC1OLdEmf4EEw3OxUuSW/1bdpVZMqWLFYKDk=";

  subPackages = [ "tools/check" ];
  env.CGO_ENABLED = 0;

  postInstall = ''
    mv "$out/bin/check" "$out/bin/tdx-verify"
  '';

  meta = {
    description = "Intel TDX quote signature, certificate, and collateral verifier";
    homepage = "https://github.com/google/go-tdx-guest";
    license = lib.licenses.asl20;
    mainProgram = "tdx-verify";
  };
}
