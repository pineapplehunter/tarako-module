{
  stdenv,
  cmake,
  pkg-config,
  libevent,
  libtarako,
}:
stdenv.mkDerivation {
  pname = "tarako-simple-attester";
  version = "0.1.0";
  src = ./.;
  nativeBuildInputs = [ cmake pkg-config ];
  buildInputs = [ libtarako libevent ];
  doInstallCheck = true;
  installCheckPhase = ''
    ${stdenv.cc.bintools}/bin/${stdenv.cc.targetPrefix}readelf -lW "$out"/bin/* > headers
    if grep -E 'INTERP|DYNAMIC' headers; then
      echo "Expected statically linked executables" >&2
      exit 1
    fi
  '';
  meta.mainProgram = "tarako-simple-attester";
}
