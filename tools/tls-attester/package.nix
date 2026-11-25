{
  lib,
  stdenv,
  cmake,
  pkg-config,
  libnghttp2,
  libtarako,
}:
stdenv.mkDerivation {
  pname = "tarako-tls-attester";
  version = "0.1.0";
  src = ./.;
  nativeBuildInputs = [ cmake pkg-config ];
  buildInputs = [ libtarako libnghttp2 ];
  doInstallCheck = true;
  installCheckPhase = ''
    ${stdenv.cc.bintools}/bin/${stdenv.cc.targetPrefix}readelf -lW "$out"/bin/* > headers
    if grep -E 'INTERP|DYNAMIC' headers; then
      echo "Expected statically linked executables" >&2
      exit 1
    fi
  '';
  meta.mainProgram = "tarako-tls-attester";
  meta.license = lib.licenses.gpl3Plus;
}
