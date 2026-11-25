{ config, lib, ... }:
let
  cfg = config.services.tarakoTdxImaLog;
in
{
  options.services.tarakoTdxImaLog = {
    enable = lib.mkEnableOption "plain HTTP IMA log for private TARAKO testing";
    package = lib.mkOption {
      type = lib.types.package;
      description = "Packaged SHA-384 IMA log server.";
    };
    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Guest address to bind. Set a private interface address for remote use.";
    };
    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.tarako-tdx-ima-log = {
      description = "TARAKO SHA-384 IMA log server (private test network)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          (lib.getExe cfg.package)
          "--listen"
          cfg.listen
          "--port"
          (toString cfg.port)
        ];
        Restart = "on-failure";
      };
    };
  };
}
