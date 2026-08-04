# IMA RTMR Kernel Patch Report

## Summary

Intel's article, "Runtime Integrity Measurement and Attestation in a Trust Domain", references an RTMR-over-IMA implementation, but does not link directly to a patch, repository, branch, or mailing list post.

The relevant text from the article is:

> The approach and implementation of RTMR over IMA can be found in the reference code from Linux Reference Stack, please check Whitepaper: Linux* Stacks for Intel(R) Trust Domain Extension 1.0 for details. The reference code may not able be upstreamed.

The article points to the whitepaper:

https://www.intel.com/content/www/us/en/content-details/787041/whitepaper-linux-stacks-for-intel-trust-domain-extension-1-0.html?DocID=787041

I did not find a public Intel-maintained standalone kernel patch for this feature. The public implementation I found and tested is:

https://github.com/acompany-develop/ima-rtmr-extend

That repository does not claim the patch came from Intel. Its files are copyrighted by Acompany Co., Ltd. and the initial commit is labeled "chore: initial public release".

## Patch Used

The project includes the experimental NixOS module `kernel/ima-rtmr-kernel.nix`.

It fetches `acompany-develop/ima-rtmr-extend` at:

```text
33101a9db9fcf1a7172aaede8fd943817d836941
```

The module converts the repository's `src/` files plus its Kconfig/Makefile patches into a Linux kernel patch and applies it through `boot.kernelPatches`.

The module enables these relevant kernel options:

```text
CONFIG_IMA=y
CONFIG_IMA_RTMR=y
CONFIG_KRETPROBES=y
CONFIG_TSM_MEASUREMENTS=y
CONFIG_TDX_GUEST_DRIVER=m
```

## Build Instructions

The TDX test's attester imports the module. Build its test driver, including the patched kernel, with:

```sh
nix build .#tdx-test-driver
```

Other NixOS configurations can apply the patch by importing `kernel/ima-rtmr-kernel.nix` and selecting a compatible kernel through `boot.kernelPackages`.

In my test, the full kernel build succeeded for Nixpkgs Linux `7.1.1` and produced:

```text
/nix/store/drmpc1l2r6aa44mqv9ap1jb0j3s05ppm-linux-7.1.1
```

The generated config contained:

```text
CONFIG_KRETPROBES=y
CONFIG_TDX_GUEST_DRIVER=m
CONFIG_TSM_MEASUREMENTS=y
CONFIG_IMA_RTMR=y
CONFIG_IMA=y
```

## Notes

The Acompany patch ships patch metadata for Linux `6.17` and `7.0`. It applied and built successfully against this flake's Nixpkgs kernel `7.1.1`, but this should be treated as experimental.

For TDX runtime use, the guest needs the TDX guest driver and `tsm-mr` measurement sysfs interface. The module expects an RTMR sysfs path such as:

```text
/sys/class/misc/tdx_guest/measurements/rtmr2:sha384
```

The implementation extends IMA measurements to RTMRs through the `tsm-mr` interface rather than through a TPM device.
