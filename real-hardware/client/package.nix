{
  lib,
  stdenv,
  cmake,
  pkg-config,
  libnghttp2,
  libtarako,
}:
stdenv.mkDerivation {
  pname = "tarako-tdx-client";
  version = "0.1.0";
  src = ./.;
  nativeBuildInputs = [ cmake pkg-config ];
  buildInputs = [ libtarako libnghttp2 ];
  meta.mainProgram = "tarako-tdx-client";
  meta.license = lib.licenses.gpl3Plus;
}
