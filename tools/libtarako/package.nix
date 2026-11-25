{
  lib,
  stdenv,
  cmake,
  openssl,
  curlMinimal,
  json_c,
  pkg-config,
}:
stdenv.mkDerivation {
  pname = "libtarako";
  version = "0.1.0";
  src = ./.;
  propagatedBuildInputs = [
    openssl
    curlMinimal
    json_c
  ];
  nativeBuildInputs = [ cmake pkg-config ];
  cmakeFlags = lib.optional stdenv.hostPlatform.isStatic "-DPKG_CONFIG_ARGN=--static";
  meta.license = lib.licenses.gpl3Plus;
}
