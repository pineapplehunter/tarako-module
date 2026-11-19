{ lib, pkgs, ... }:

let
  imaRtmrSrc = pkgs.fetchFromGitHub {
    owner = "acompany-develop";
    repo = "ima-rtmr-extend";
    rev = "33101a9db9fcf1a7172aaede8fd943817d836941";
    hash = "sha256-PZBJBcv69b2bh5NcIR075hFRU22crSQWLddXIXohi5I=";
  };

  patchVersion = "7.0";

  imaRtmrPatch = pkgs.stdenvNoCC.mkDerivation {
    pname = "ima-rtmr-kernel.patch";
    version = imaRtmrSrc.rev;

    dontUnpack = true;
    dontConfigure = true;
    dontBuild = true;

    installPhase = ''
      runHook preInstall

      src_dir="${imaRtmrSrc}/src"
      out_dir="security/integrity/ima_rtmr"
      work="$(mktemp -d)"

      touch "$out"
      cp "${imaRtmrSrc}/kernel/patches/${patchVersion}/kconfig.patch" "$out"
      printf '\n' >> "$out"
      cat "${imaRtmrSrc}/kernel/patches/${patchVersion}/makefile.patch" >> "$out"

      for file in "$src_dir"/*; do
        name="$(basename "$file")"
        mkdir -p "$work/$out_dir"
        cp "$file" "$work/$out_dir/$name"
        if [ "$name" = main.c ]; then
          # IMA populates its digest banks at late_initcall. The built-in
          # TDX guest driver registers the RTMR sysfs device earlier.
          substituteInPlace "$work/$out_dir/$name" \
            --replace-fail 'module_init(ima_rtmr_init);' 'late_initcall_sync(ima_rtmr_init);'
        fi
        diff -u /dev/null "$work/$out_dir/$name" \
          | sed "s|$work/|b/|" >> "$out" || true
      done
      cat ${./ima-rtmr-early-sysfs.patch} >> "$out"

      runHook postInstall
    '';
  };
in
{
  boot.kernelPatches = [
    {
      name = "ima-rtmr";
      patch = imaRtmrPatch;
      structuredExtraConfig = with lib.kernel; {
        IMA = yes;
        IMA_APPRAISE = yes;
        IMA_APPRAISE_BOOTPARAM = yes;
        IMA_DEFAULT_HASH_SHA256 = yes;
        IMA_LSM_RULES = yes;
        IMA_MEASURE_ASYMMETRIC_KEYS = yes;
        IMA_NG_TEMPLATE = yes;
        IMA_QUEUE_EARLY_BOOT_KEYS = yes;
        IMA_READ_POLICY = yes;
        IMA_WRITE_POLICY = yes;
        IMA_RTMR = yes;
        INTEL_TDX_GUEST = yes;
        KPROBES = yes;
        KRETPROBES = yes;
        TDX_GUEST_DRIVER = lib.mkForce yes;
      };
    }
  ];
}
