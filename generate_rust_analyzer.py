#!/usr/bin/env python3
"""generate_rust_analyzer - Generates rust-project.json for the tarako kernel module.

Usage (from the nix devShell):
    python3 generate_rust_analyzer.py > rust-project.json
"""

import json
import os
import pathlib
import sys

required_vars = {
    "RUST_KERNEL_SRCTREE": "path to the full kernel source tree",
    "RUST_KERNEL_OBJTREE": "path to the kernel build tree",
    "RUST_SYSROOT": "rustc --print sysroot",
    "RUST_LIB_SRC": "path to rust library sources",
}
missing = [f"  ${k}  ({v})" for k, v in required_vars.items() if k not in os.environ]
if missing:
    print("error: the following environment variables are required:", file=sys.stderr)
    for m in missing:
        print(m, file=sys.stderr)
    print(file=sys.stderr)
    print("Run this from the nix devShell:", file=sys.stderr)
    print("  nix develop . --command python3 generate_rust_analyzer.py > rust-project.json", file=sys.stderr)
    sys.exit(1)

SRCTREE     = pathlib.Path(os.environ["RUST_KERNEL_SRCTREE"])
OBJTREE     = pathlib.Path(os.environ["RUST_KERNEL_OBJTREE"])
SYSROOT     = pathlib.Path(os.environ["RUST_SYSROOT"])
SYSROOT_SRC = pathlib.Path(os.environ["RUST_LIB_SRC"])
EXTMOD      = pathlib.Path(__file__).resolve().parent / "driver"


def load_cfgs() -> list[str]:
    path = OBJTREE / "include/generated/rustc_cfg"
    cfgs: list[str] = []
    with open(path) as f:
        for line in f:
            cfgs.append(line.strip().replace("--cfg=", ""))
    return cfgs


def main():
    generated_cfg = load_cfgs()

    has_vendored = (SRCTREE / "rust/proc-macro2/lib.rs").exists()

    # ── helpers ─────────────────────────────────────────────────────
    crates: list[dict] = []
    last_index = -1

    def reg(c: dict) -> dict:
        nonlocal last_index
        last_index += 1
        crates.append(c)
        return {"crate": last_index, "name": c["display_name"]}

    def make_crate(
        display_name: str,
        root_module: pathlib.Path,
        deps: list[dict],
        *,
        cfg: list[str] | None = None,
        is_workspace_member: bool = True,
        edition: str = "2021",
        extra: dict | None = None,
    ) -> dict:
        c: dict = {
            "display_name": display_name,
            "root_module": str(root_module.resolve()),
            "is_workspace_member": is_workspace_member,
            "deps": deps,
            "cfg": cfg if cfg is not None else [],
            "edition": edition,
            "env": {"RUST_MODFILE": "This is only for rust-analyzer"},
        }
        if extra:
            c.update(extra)
        return c

    def sysroot_crate(name: str, deps: list[dict], *, edition: str = "2021") -> dict:
        return reg(make_crate(
            name,
            SYSROOT_SRC / name / "src/lib.rs",
            deps,
            is_workspace_member=False,
            edition=edition,
        ))

    def internal_crate(
        display_name: str,
        root_module: pathlib.Path,
        deps: list[dict],
        *,
        cfg: list[str] | None = None,
        edition: str = "2021",
    ) -> dict:
        return reg(make_crate(
            display_name,
            root_module, deps,
            cfg=cfg, is_workspace_member=False, edition=edition,
        ))

    def proc_macro_crate(
        display_name: str,
        root_module: pathlib.Path,
        deps: list[dict],
        dylib: pathlib.Path,
        *,
        cfg: list[str] | None = None,
        edition: str = "2021",
    ) -> dict:
        return reg(make_crate(
            display_name, root_module, deps,
            cfg=cfg, is_workspace_member=False, edition=edition,
            extra={"is_proc_macro": True, "proc_macro_dylib_path": str(dylib)},
        ))

    def generated_crate(
        display_name: str,
        deps: list[dict],
    ) -> dict:
        root = SRCTREE / "rust" / display_name / "lib.rs"
        c = make_crate(
            display_name, root, deps,
            cfg=generated_cfg, is_workspace_member=True, edition="2021",
            extra={
                "source": {
                    "include_dirs": [
                        str(SRCTREE / "rust" / display_name),
                        str(OBJTREE / "rust"),
                    ],
                    "exclude_dirs": [],
                },
            },
        )
        c["env"]["OBJTREE"] = str(OBJTREE.resolve())
        return reg(c)

    # ── 1. Sysroot crates ──────────────────────────────────────────
    core       = sysroot_crate("core", [])
    alloc      = sysroot_crate("alloc", [core])
    std        = sysroot_crate("std", [alloc, core])
    proc_macro = sysroot_crate("proc_macro", [core, std])

    # ── 2. Kernel-internal crates ───────────────────────────────────
    compiler_builtins = internal_crate(
        "compiler_builtins",
        SRCTREE / "rust/compiler_builtins.rs",
        [core],
    )

    if has_vendored:
        proc_macro2 = internal_crate(
            "proc_macro2",
            SRCTREE / "rust/proc-macro2/lib.rs",
            [core, alloc, std, proc_macro],
        )
        quote_crate = internal_crate(
            "quote",
            SRCTREE / "rust/quote/lib.rs",
            [core, alloc, std, proc_macro, proc_macro2],
            edition="2018",
        )
        syn = internal_crate(
            "syn",
            SRCTREE / "rust/syn/lib.rs",
            [std, proc_macro, proc_macro2, quote_crate],
        )
        macros = proc_macro_crate(
            "macros",
            SRCTREE / "rust/macros/lib.rs",
            [std, proc_macro, proc_macro2, quote_crate, syn],
            OBJTREE / "rust/libmacros.so",
        )
        pin_init_internal = proc_macro_crate(
            "pin_init_internal",
            SRCTREE / "rust/pin-init/internal/src/lib.rs",
            [std, proc_macro, proc_macro2, quote_crate, syn],
            OBJTREE / "rust/libpin_init_internal.so",
        )
    else:
        macros = proc_macro_crate(
            "macros",
            SRCTREE / "rust/macros/lib.rs",
            [std, proc_macro],
            OBJTREE / "rust/libmacros.so",
        )
        pin_init_internal = proc_macro_crate(
            "pin_init_internal",
            SRCTREE / "rust/pin-init/internal/src/lib.rs",
            [std, proc_macro],
            OBJTREE / "rust/libpin_init_internal.so",
        )

    build_error = internal_crate(
        "build_error",
        SRCTREE / "rust/build_error.rs",
        [core, compiler_builtins],
    )

    pin_init = internal_crate(
        "pin_init",
        SRCTREE / "rust/pin-init/src/lib.rs",
        [core, compiler_builtins, pin_init_internal, macros],
    )

    ffi = internal_crate(
        "ffi",
        SRCTREE / "rust/ffi.rs",
        [core, compiler_builtins],
    )

    bindings = generated_crate("bindings", [core, ffi, pin_init])
    uapi     = generated_crate("uapi", [core, ffi, pin_init])
    kernel   = generated_crate("kernel", [core, macros, build_error, pin_init, ffi, bindings, uapi])

    # ── 3. External module crate: tarako ────────────────────────────
    tarako_root = EXTMOD / "src/lib.rs"
    reg(make_crate(
        "tarako",
        tarako_root,
        [core, kernel, pin_init],
        cfg=generated_cfg,
        is_workspace_member=True,
    ))

    # ── Output ──────────────────────────────────────────────────────
    out = {
        "crates": crates,
        "sysroot": str(SYSROOT),
    }
    json.dump(out, sys.stdout, sort_keys=True, indent=4)


if __name__ == "__main__":
    main()
