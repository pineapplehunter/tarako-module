{
  pkgs,
  lib,
  config,
  ...
}:
let
  cfg = config.custom.ima;
in
{
  options.custom.ima.enable = lib.mkEnableOption "FS-verity";
  config = lib.mkIf cfg.enable {
    boot.kernelPatches = [
      {
        name = "ima";
        patch = null;
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
        };
        features.ima = true;
      }
    ];
    environment.systemPackages = [ pkgs.ima-evm-utils ];
  };
}
