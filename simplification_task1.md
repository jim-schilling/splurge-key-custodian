## Simplification & Decomposition Plan (Task 1)

This document outlines a pragmatic plan to simplify and decompose `splurge_key_custodian/key_custodian.py` and `splurge_key_custodian/key_rotation.py` into smaller, testable modules with clear responsibilities. The plan is incremental, test-first, and aims to maintain behavior while reducing complexity.

### Goals
- Reduce module size and cognitive load.
- Separate concerns: persistence, crypto, validation, orchestration.
- Stabilize public APIs for CLI and integrations.
- Improve unit and integration test coverage and speed.

### Non-goals (for Task 1)
- Rewriting crypto primitives or persistence formats.
- Any breaking CLI or public API changes.

## Current High-level Responsibilities

- `key_custodian.py`
  - Master key lifecycle (init/load/validation).
  - Credentials CRUD and index maintenance.
  - Backups and filesystem ops (delegated to `FileManager`).
  - Rotation orchestration pass-through to `KeyRotationManager`.

- `key_rotation.py`
  - Rotation orchestration and transaction/rollback mechanics.
  - Backup creation and retention.
  - Per-credential re-encryption strategies (master change, bulk new key).
  - Rotation history management.

## Target Decomposition

- `splurge_key_custodian/services/`
  - `master_key_service.py`
    - Load/validate/create master key.
    - Derive keys from password, manage placeholder validation.
    - Public: `get_current_master_key()`, `ensure_master_key(...)`.
  - `credential_service.py`
    - CRUD for credentials (create/read/update/delete).
    - Name uniqueness checks (using index service).
    - Public: `create(...)`, `read(...)`, `update(...)`, `delete(...)`, `list()`, `find_by_name(...)`.
  - `index_service.py`
    - Load/save/rebuild index, detect drift.
    - Public: `load()`, `save()`, `rebuild()`, `should_rebuild()`.
  - `backup_service.py`
    - Wraps `FileManager.backup_*` use-cases for non-rotation backups.
  - `rotation/transaction.py`
    - Move `RotationTransaction` class here.
  - `rotation/backup.py`
    - Create/restore rotation backups (master and bulk), expiration logic.
  - `rotation/operations.py`
    - Stateless functions to re-encrypt: `re_encrypt_with_new_master(...)`, `re_encrypt_for_password_change(...)`, `re_encrypt_with_new_key(...)`.
  - `rotation/manager.py`
    - Thin orchestration that composes transaction, backup, operations, and history.

- `splurge_key_custodian/key_custodian.py`
  - Becomes a façade that composes the services and delegates.
  - Minimizes private helpers; move logic into services.

- Keep existing modules:
  - `file_manager.py`, `crypto_utils.py`, `models.py`, `validation_utils.py` remain and are reused.

## Public API Stability

- Keep `KeyCustodian` public methods stable for Task 1: initialization, CRUD, rotations, history, backups.
- Keep `KeyRotationManager` import path working by re-exporting from `rotation/manager.py`.

## Incremental Refactor Steps

1) Create scaffolding modules and relocate code without behavior changes
   - Add `services/rotation/transaction.py` and move `RotationTransaction` with same interface.
   - Add `services/rotation/operations.py` and move `_re_encrypt_*` helpers as top-level functions.
   - Add `services/rotation/backup.py` and move backup/restore helpers (`_create_*_backup`, `_restore_credential_files`, rollback helpers).
   - Add `services/rotation/manager.py` and move `KeyRotationManager` to use the new helpers via composition.
   - Add simple `__init__.py` files to preserve package imports; re-export `KeyRotationManager` from `key_rotation.py` for backward compatibility.

2) Extract index responsibilities
   - Create `services/index_service.py` and move `_load_credentials_index*`, `_rebuild_index_from_files*`, `_should_rebuild_index*`.
   - Update `KeyCustodian` to depend on `IndexService` for index load/save/rebuild.

3) Extract master key responsibilities
   - Create `services/master_key_service.py` and move `_initialize_master_key*` logic.
   - Encapsulate derive/validate placeholder logic and return current `MasterKey`.
   - `KeyCustodian` becomes a consumer of `MasterKeyService`.

4) Extract credential CRUD logic
   - Create `services/credential_service.py` and migrate `create_credential`, `read_credential`, `update_credential`, `delete_credential`, `find_credential_by_name`, `list_credentials`.
   - Preserve `KeyCustodian` API by delegating to `CredentialService`.

5) Add thin backup service for non-rotation backups
   - Move `backup_credentials` to `BackupService` which wraps `FileManager.backup_files`.

6) Clean up `key_custodian.py`
   - Remove moved helpers, keep only façade + minimal glue.
   - Ensure properties (`data_directory`, `master_key_id`, `credential_count`, `iterations`) read from services.

## Testing Strategy

- Keep existing tests green at every step.
- Add new unit tests per service:
  - `tests/unit/services/test_master_key_service.py`
  - `tests/unit/services/test_index_service.py`
  - `tests/unit/services/test_credential_service.py`
  - `tests/unit/services/rotation/test_operations.py`
  - `tests/unit/services/rotation/test_backup.py`
  - `tests/unit/services/rotation/test_transaction.py`
- Keep integration tests targeting `KeyCustodian` and CLI unchanged.

## Acceptance Criteria (Task 1)

- All tests pass (unit, integration, functional).
- `KeyCustodian` reduced to orchestration façade (< ~300 lines).
- `KeyRotationManager` moved into `services/rotation/manager.py`; legacy import path continues to work.
- No public API or CLI behavior changes.
- Coverage at least maintained; new services have dedicated tests.

## Risks & Mitigations

- Implicit coupling between index and CRUD: resolve via `IndexService` injected into `CredentialService`.
- Iterations/backward compatibility: keep existing default/None handling and pass iterations via service boundaries explicitly.
- Transactional correctness: ensure `RotationTransaction` behavior unchanged; add tests for rollback/commit paths.

## Work Breakdown (PR slices)

- PR1: Introduce `services/rotation/*` and rewire `KeyRotationManager` (no behavior change). Re-export in `key_rotation.py`.
- PR2: Introduce `IndexService` and move index helpers; adapt `KeyCustodian` to delegate index ops.
- PR3: Introduce `MasterKeyService`; adapt `KeyCustodian` init path and master key accessors.
- PR4: Introduce `CredentialService`; migrate CRUD; keep `KeyCustodian` façade methods delegating.
- PR5: Introduce `BackupService`; migrate non-rotation backup call.
- PR6: Final cleanup: remove dead/private helpers, tighten typing and docstrings, ensure imports and lints.

## Coding Guidelines (apply to new modules)

- Follow existing project style and user rules: PEP8, Google-style docstrings, explicit typing, guard clauses.
- Group imports standard -> third-party -> local; avoid side effects at module import time.
- Keep modules focused; prefer small, stateless helpers where possible.


