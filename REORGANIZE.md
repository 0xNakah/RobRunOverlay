# Repository reorganization

This change is a pure path restructure: it moves files and updates references.
It does not change any source code, and it intentionally makes no functional
improvement to the mapper, the driver or the overlay. `mapper-analysis/`
preserves the old mapper unchanged for study; no operational replacement is
maintained.

## Move map

| Old path | New path | Contents |
|---|---|---|
| `2_src_port/` | `overlay/` | Overlay reader, renderer, menu, build script |
| `3_src_driver/` | `driver/` | WmPort kernel driver and build script |
| `5_src_loader/` | `launcher/` | AIO launcher solution and source |
| `4_src_mapper/` | `mapper-analysis/` | kdmapper-class mapper, kept as prior art |
| `offsets/` | `data/offsets/` | Field and rig provenance JSON |
| `tools/` | `scripts/` | Offset generation and audit scripts |
| `1_run/` | `artifacts/run/` | Prebuilt binaries, configs, launch scripts |
| `dist/` | `artifacts/dist/` | Release artifacts |
| `BUILD.md` | `docs/BUILD.md` | Build guide |
| `SINGLE_BUILD.md` | `docs/SINGLE_BUILD.md` | Single-build guide |

`README.md` and `.gitignore` are updated in this commit to match. `docs/`
and `README.md` stay in place.

## How to apply

1. Check out this branch: `git checkout reorg/clean-layout`
2. Run at the repo root: `pwsh ./reorganize.ps1` (or `powershell -File reorganize.ps1`)
3. Review: `git status` (Git should report the moves as renames)
4. Rebuild every component; fix any hardcoded old path you find
5. Commit and push, then open a PR to the default branch

## Known follow-ups (not done here)

- Build scripts (`build_port.bat`, `build_aio.bat`, `build_driver.bat`,
  `build_loader.bat`) may contain root-relative references to the old folder
  names; check them after rebuilding.
- The old README pointed at `3_src_driver/smx.h`; the actual wire contract file
  in the tree is `wm.h`. The updated README now points at `driver/wm.h`.
- Consider removing committed build outputs (`*.obj`, `*.res`, executables,
  `RCa36420`) in a separate cleanup commit so the source tree only carries
  source. They are preserved here because this commit moves, not deletes.
- Add a LICENSE file separately; none exists and the README asks readers to
  preserve third-party attribution.
