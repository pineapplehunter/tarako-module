{ OVMF-inteltdx }:
# Build TDVF from EDK II source, not Ubuntu's prebuilt OVMF.tdx.fd.
# The nixpkgs source revision and submodules are pinned by flake.lock.
# OVMF-inteltdx builds BaseTools, sources edksetup.sh, then runs:
#   build -p OvmfPkg/IntelTdx/IntelTdxX64.dsc -a X64 -t GCC -b RELEASE
# This is the dedicated TDVF Config-B target documented in
# https://github.com/tianocore/edk2/blob/master/OvmfPkg/IntelTdx/README.md
OVMF-inteltdx.fd
