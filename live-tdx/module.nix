{ config, lib, ... }:
let
  cfg = config.services.tarakoTdxVerifier;
  instance = lib.types.submodule {
    options = {
      port = lib.mkOption {
        type = lib.types.port;
        default = 5102;
        description = "Loopback port inside the verifier VM.";
      };
      policyFile = lib.mkOption {
        type = lib.types.str;
        description = "Absolute path to the operator-reviewed policy JSON.";
      };
      signingKeyFile = lib.mkOption {
        type = lib.types.str;
        description = "Absolute path to the P-256 PEM private key outside the Nix store.";
      };
    };
  };
in
{
  options.services.tarakoTdxVerifier = {
    enable = lib.mkEnableOption "TARAKO live TDX quote appraisal";
    package = lib.mkOption {
      type = lib.types.package;
      description = "Packaged TARAKO TDX verifier and Intel DCAP helper.";
    };
    qcnlConfigFile = lib.mkOption {
      type = lib.types.str;
      description = "Absolute path to the operator's Intel QCNL configuration.";
    };
    instances = lib.mkOption {
      type = lib.types.attrsOf instance;
      default = { };
      description = "Local verifier instances; negative tests may use isolated policies.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.instances != { };
        message = "Configure at least one TARAKO verifier instance.";
      }
      {
        assertion = lib.hasPrefix "/" cfg.qcnlConfigFile;
        message = "TARAKO QCNL configuration must have an absolute path.";
      }
    ]
    ++ lib.mapAttrsToList (name: value: {
      assertion =
        builtins.match "[a-zA-Z0-9_-]+" name != null
        && lib.hasPrefix "/" value.policyFile
        && lib.hasPrefix "/" value.signingKeyFile
        && !lib.hasPrefix "/nix/store/" value.signingKeyFile;
      message = "Invalid TARAKO verifier instance name, policy path or key path (${name}).";
    }) cfg.instances;

    systemd.services = lib.mapAttrs' (
      name: value:
      lib.nameValuePair "tarako-tdx-verifier-${name}" {
        description = "TARAKO live TDX verifier (${name})";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          DynamicUser = true;
          LoadCredential = [
            "policy:${value.policyFile}"
            "signing-key:${value.signingKeyFile}"
          ];
          BindReadOnlyPaths = [ "${cfg.qcnlConfigFile}:/etc/sgx_default_qcnl.conf" ];
          CacheDirectory = "tarako-tdx-verifier-${name}";
          Environment = "XDG_CACHE_HOME=/var/cache/tarako-tdx-verifier-${name}";
          ExecStart = "${lib.getExe cfg.package} --listen 127.0.0.1 --port ${toString value.port} --policy %d/policy --signing-key %d/signing-key";
          Restart = "on-failure";
        };
      }
    ) cfg.instances;
  };
}
