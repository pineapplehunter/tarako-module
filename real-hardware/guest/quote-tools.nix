# Quote utilities for interactive TDX VMs.
{ pkgs, ... }:
let
  tpm-quote = pkgs.writers.writePython3Bin "tpm-quote" { } ./tpm-quote.py;
  tarako-quote = pkgs.writers.writePython3Bin "tarako-quote" { } ./tarako-quote.py;
in
{
  environment.systemPackages = [
    tarako-quote
    tpm-quote
    pkgs.tdx-attest
    pkgs.tdx-verify
    pkgs.tpm2-tools
  ];
}
