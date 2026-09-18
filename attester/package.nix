{ buildGoModule }:
buildGoModule {
  pname = "tarako-attester";
  version = "0.1.0";

  src = ./.;
  vendorHash = null;

  env.CGO_ENABLED = 0;

  postInstall = ''
    mv $out/bin/attester $out/bin/tarako-attester
  '';
}
