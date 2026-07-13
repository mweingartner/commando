## 1. Directives (doctrine)

- [x] 1.1 Author `crates/mpd/assets/directives/protocol.md` (full MPD doctrine)
- [x] 1.2 Author `crates/mpd/assets/directives/personas/<persona>.md` for each persona
- [x] 1.3 Add a `directives` module: bundled table + project-first resolution via `read_capped`, bundled fallback
- [x] 1.4 `scaffold::init` installs directives to `.mpd/directives/` (write_new, non-destructive)
- [x] 1.5 `mpd next [--full]` surfaces the persona directive; `mpd doctor` reports directive status

## 2. Configurable models

- [x] 2.1 `config.rs`: add `models: Map<harness, Map<persona, model>>` and `model_fallbacks: Map<model, model>` (serde default)
- [x] 2.2 `harness::model_for(&Config, harness, phase)`: config lookup by persona, built-in tier fallback; thread `Config` through `brief`/`cmd_next`
- [x] 2.3 `scaffold::init` seeds explicit default `models` + `model_fallbacks` in `.mpd/config.json`

## 3. Verification

- [x] 3.1 Unit tests: directive resolution (project override, symlink fallback), model resolution (config, default, fallback note)
- [x] 3.2 e2e: `next --full` inlines directive; `models` config changes the reported model; init installs directives + seeds models
- [x] 3.3 Security (code) review of the new file I/O; Documentation + Doc Validation; full suite green; archive
