{
  lib,
  gcc13Stdenv,
  fetchurl,
  pkg-config,
  python3Packages,
  meson,
  ninja,
  flex,
  bison,
  perl,
  glib,
  pixman,
  zlib,
  dtc,
  vde2,
  libslirp,
}:
let
  ubuntuVersion = "8.2.2+ds-0ubuntu1.4+tdx1.1";
  ubuntuPatches = fetchurl {
    url = "https://ppa.launchpadcontent.net/kobuk-team/tdx-release/ubuntu/pool/main/q/qemu/qemu_${ubuntuVersion}.debian.tar.xz";
    hash = "sha256-4r9O5vQNSKxoNID2slzJYo8fDMRRWbYjZTtpi5fTCdo=";
  };
in
# The vendor TDX ABI matches Ubuntu's 6.8 -intel host kernel, not upstream KVM.
# Use GCC 13, as on Ubuntu Noble, rather than a newer C-language default.
gcc13Stdenv.mkDerivation {
  pname = "qemu-tdx";
  version = "8.2.2-tdx1.1";

  # The full upstream release includes the BIOS/option ROMs removed by +ds.
  # Apply the complete Ubuntu patch series, including all vendor TDX patches.
  src = fetchurl {
    url = "https://download.qemu.org/qemu-8.2.2.tar.xz";
    hash = "sha256-hHNGwbgsGlSyw49u29hVSe3rF0MLfU09oSYg4pYrxPM=";
  };

  postUnpack = ''
    tar -xf ${ubuntuPatches} -C "$sourceRoot"
  '';
  postPatch = ''
    while read -r patch rest; do
      case "$patch" in ""|\#*) continue ;; esac
      patch -p1 < "debian/patches/$patch"
    done < debian/patches/series
    # The vendor GetQuote path predates the framed Intel QGS protocol.
    patch -p1 < ${./qemu-qgs-protocol.patch}
    patch -p1 < ${./qemu-qgs-diagnostics.patch}
    cp ${./tdx-qgs-protocol.h} target/i386/kvm/tdx-qgs-protocol.h
    patchShebangs .
  '';

  nativeBuildInputs = [
    pkg-config
    python3Packages.python
    python3Packages.distlib
    python3Packages.setuptools
    meson
    ninja
    flex
    bison
    perl
  ];
  buildInputs = [
    glib
    pixman
    zlib
    dtc
    vde2
    libslirp
  ];

  # QEMU drives Meson/Ninja through its own configure script and Makefile.
  dontUseMesonConfigure = true;
  dontUseNinjaBuild = true;
  dontUseNinjaInstall = true;
  enableParallelBuilding = true;
  preConfigure = ''
    unset CPP
  '';
  configureFlags = [
    "--target-list=x86_64-softmmu"
    "--with-pkgversion=Ubuntu-2:${ubuntuVersion}"
    "--without-default-features"
    "--disable-download"
    "--disable-docs"
    "--disable-guest-agent"
    "--disable-strip"
    "--disable-werror"
    "--enable-kvm"
    "--enable-tcg"
    "--enable-pixman"
    "--enable-fdt"
    "--enable-slirp"
    "--enable-vde"
    "--enable-tpm"
    "--enable-vhost-kernel"
    "--enable-vhost-net"
    "--enable-tools"
  ];

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    $CC -std=c11 -Wall -Wextra -Werror -I target/i386/kvm \
      ${./qgs-protocol-test.c} -o qgs-protocol-test
    ./qgs-protocol-test
    $out/bin/qemu-system-x86_64 --version | grep -F 'tdx1.1'
    $out/bin/qemu-system-x86_64 -netdev help | grep -w vde
    # Instance properties such as quote-generation-socket are not listed by
    # -object help. Instantiate one under TCG without requesting a TDX VM.
    printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"quit"}' | \
      timeout 30 $out/bin/qemu-system-x86_64 \
        -machine none,accel=tcg -display none -nodefaults -S \
        -object '{"qom-type":"tdx-guest","id":"tdx0","quote-generation-socket":{"type":"vsock","cid":"2","port":"4050"}}' \
        -qmp stdio > qmp-output
    grep -F '"return": {}' qmp-output
    $out/bin/qemu-system-x86_64 -device help > devices
    grep -F tpm-crb devices
    grep -F vhost-vsock-pci devices
    $out/bin/qemu-img create -f qcow2 "$TMPDIR/smoke.qcow2" 1M
    runHook postInstallCheck
  '';

  meta = {
    description = "QEMU 8.2.2 with Ubuntu tdx1.1 patches for the vendor TDX host ABI";
    homepage = "https://github.com/canonical/tdx";
    license = lib.licenses.gpl2Plus;
    platforms = [ "x86_64-linux" ];
    mainProgram = "qemu-system-x86_64";
  };
}
