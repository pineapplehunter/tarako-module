{
  lib,
  stdenv,
  fetchurl,
  dpkg,
  autoPatchelfHook,
  openssl,
  curl,
  enableTestOverride ? false,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "tarako-dcap-verify";
  version = "1.27.1";

  # Intel's Ubuntu 24.04 release, repackaged without installing an SGX runtime
  # or a QvE. The CLI uses only the software QVL and the default QPL/QCNL.
  src = fetchurl {
    url = "https://download.01.org/intel-sgx/sgx-dcap/${finalAttrs.version}/linux/distro/ubuntu24.04-server/sgx_debian_local_repo.tgz";
    hash = "sha256-BLMdECQSeM9ZwAxJQj46kkxW2mnm/7akkfzgnCX1gRQ=";
  };
  nativeBuildInputs = [
    dpkg
    autoPatchelfHook
  ];
  buildInputs = [
    openssl
    stdenv.cc.cc.lib
  ];

  # QCNL uses dlopen rather than DT_NEEDED for libcurl.
  appendRunpaths = [ "${lib.getLib curl}/lib" ];

  dontConfigure = true;
  buildPhase = ''
    runHook preBuild
    for pkg in libsgx-dcap-quote-verify libsgx-dcap-quote-verify-dev libsgx-dcap-default-qpl libsgx-headers; do
      dpkg-deb -x pool/main/libs/''${pkg%-dev}/''${pkg}_*_amd64.deb extracted
    done
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin" "$out/lib" "$out/share/tarako-dcap-verify"
    cp -P extracted/usr/lib/x86_64-linux-gnu/*.so* "$out/lib/"
    cp extracted/etc/sgx_default_qcnl.conf "$out/share/tarako-dcap-verify/"
    cp -r extracted/usr/share/doc "$out/share/"
    $CC -std=c11 -Wall -Wextra -Werror -O2 \
      -isystem extracted/usr/include \
      -DQPL_PATH=\"$out/lib/libdcap_quoteprov.so.1\" \
      ${lib.optionalString enableTestOverride "-DTARAKO_DCAP_TEST_OVERRIDE"} \
      ${./verify.c} -L"$out/lib" -Wl,-rpath,"$out/lib" \
      -lsgx_dcap_quoteverify -o "$out/bin/tarako-dcap-verify"
    runHook postInstall
  '';

  meta = {
    description = "Strict software verification of Intel TDX quotes";
    platforms = [ "x86_64-linux" ];
    mainProgram = "tarako-dcap-verify";
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
})
