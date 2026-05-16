{
  pkgs,
  lib,
  config,
  ...
}:
let
  cfg = config.custom.fsverity;
in
{
  options.custom.fsverity.enable = lib.mkEnableOption "FS-verity";
  config = lib.mkIf cfg.enable {
    boot.kernelPatches = [
      {
        name = "fsverity";
        patch = null;
        structuredExtraConfig = with lib.kernel; {
          FS_VERITY = yes;
        };
      }
    ];
    environment.systemPackages = [ pkgs.fsverity-utils ];
  };
}
