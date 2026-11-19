{
  pkgsStatic,
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
  enableParallelBuilding = true;
  makeFlags = [ "PREFIX=${placeholder "out"}" ];
}
