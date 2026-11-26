{ lib, ... }:
{
  boot.kernelParams = [ "ima_hash=sha384" ];
  boot.kernelPatches = [
    {
      name = "ima-rtmr";
      patch = ./ima-rtmr2.patch;
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
        # Replay is defined over one complete, fresh-boot measurement list.
        IMA_KEXEC = lib.mkForce no;
        IMA_STAGING = lib.mkForce no;
        TDX_GUEST_DRIVER = lib.mkForce yes;
      };
    }
  ];
}
