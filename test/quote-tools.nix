# Shared quote utilities for benchmark and interactive TDX VMs.
{ pkgs, ... }:
let
  tpm-quote = pkgs.writers.writePython3Bin "tpm-quote" { } ./tpm-quote.py;
  tarako-quote = pkgs.writers.writePython3Bin "tarako-quote" { } ./tarako-quote.py;
  quote-bench = pkgs.writers.writePython3Bin "quote-bench" { } ./quote-bench.py;
  bench-tpm-quote = pkgs.writeShellScriptBin "bench-tpm-quote" ''
    exec ${quote-bench}/bin/quote-bench tpm "$@"
  '';
  bench-tarako-quote = pkgs.writeShellScriptBin "bench-tarako-quote" ''
    exec ${quote-bench}/bin/quote-bench tarako "$@"
  '';
in
{
  environment.systemPackages = [
    bench-tarako-quote
    bench-tpm-quote
    tarako-quote
    tpm-quote
    quote-bench
    pkgs.hyperfine
    pkgs.time
    pkgs.tpm2-tools
  ];
}
