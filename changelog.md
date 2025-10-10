# Changelog

This file details the changelog of fiit.

---

## 0.3.0 - 2025-10-10

**Full Changelog**: https://github.com/firmware-crunch/fiit/compare/0.1.0...0.3.0

### Added

- Add `machine` subpackage that provides an abstraction for machine, devices and cpu
- Add `dev` subpackage that provides reusable devices over the `machine` abstraction
- Add `emunicorn` subpackage that implements access to emulated Unicorn cpu
- Provide reusable introspection tools over the `machine` abstraction
- Add `FiitCpuFactory` interface to build configurable cpu instance
- Add new plugin interface to build complex hardware and introspection scenario


## 0.2.0 - 2025-07-16

**Full Changelog**: https://github.com/firmware-crunch/fiit/compare/0.1.0...0.2.0

### Added

- Add `fiit_console` a Jupyter client that provides custom terminal behaviours ([7b80cd2](https://github.com/firmware-crunch/fiit/commit/7b80cd2)) ([d302e48](https://github.com/firmware-crunch/fiit/commit/d302e48))
- Add new interfaces to write plugin dependency definition ([7eb8905](https://github.com/firmware-crunch/fiit/commit/7eb8905))

### Changed

- Rename the `emu` option of the `fiit` command to `run` ([fc0cca5](https://github.com/firmware-crunch/fiit/commit/fc0cca5))
- Upgrade `cmsis-svd` dependency from commit `ca0b0b0` to version `0.6` ([06f4887](https://github.com/firmware-crunch/fiit/commit/06f4887))
- **Breaking:** Upgrade `python` dependency from `3.8` to `3.9` ([7eb8905](https://github.com/firmware-crunch/fiit/commit/7eb8905))
- Provide automatic plugin instantiation order based on their dependencies ([7eb8905](https://github.com/firmware-crunch/fiit/commit/7eb8905))

---

## 0.1.0 - 2024-09-23

- Initial public release ([aaa8175](https://github.com/firmware-crunch/fiit/commit/aaa8175))
