{
  pkgsStatic,
  openssl,
  binutils,
  pkg-config,
}:
pkgsStatic.stdenv.mkDerivation {
  pname = "tarako-tls-attester";
  version = "0.1.0";
  src = ./.;
  buildInputs = with pkgsStatic; [
    openssl
    curlMinimal
    json_c
  ];
  nativeBuildInputs = [ pkg-config ];
  nativeCheckInputs = [ openssl.bin binutils ];
  enableParallelBuilding = true;
  doCheck = true;
  makeFlags = [ "PREFIX=${placeholder "out"}" ];
}
