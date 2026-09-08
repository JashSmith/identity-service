# Cryptographic Key Lifecycle Management

## Overview

The facade orchestrates Keycloak realm RSA signing keys. Vault is the authoritative source of key material. Keycloak remains the signer.

### Interim gap (documented)

Until the `company-vault-rsa-key-provider` Java SPI ships, imported private material transits through Keycloak Admin REST `components` (`org.keycloak.keys.impl.RsaKeyProviderFactory` config `privateKey`) and is persisted in Keycloak's database (`component_config`) on Oracle. The Vault SPI will remove this persistence by having Keycloak read from Vault at runtime.

## State diagram

```mermaid
stateDiagram-v2
    [*] --> Generated
    Generated --> VaultStored
    VaultStored --> Passive : stage
    Passive --> Validated : validate (JWKS)
    Validated --> Active : activate
    Active --> InGrace : previous passivated
    InGrace --> Retiring --> Retired --> Disabled --> Destroyed
    Passive --> RotationAborted
    Validated --> RotationAborted
    ValidationFailed --> RollbackPending --> Passive
    Retired --> Destroyed
    Disabled --> Destroyed
```

## Rotation sequence

Create -> Stage(Passive) -> Validate(JWKS) -> Activate -> Poll convergence -> Passivate(previous) -> Wait(grace) -> Retire -> Disable -> Destroy

## Java SPI contract (follow-up)

`VaultRsaKeyProviderFactory` / `VaultRsaKeyProvider` configured with `vault-addr`, `vault-token` or AppRole, `key-path-prefix`, TLS, timeouts. Fail-safe: node with no valid key fails readiness rather than self-generating. Release-pinned to Keycloak 26.x.

## Runbooks

- **Normal rotate**: `POST /api/admin/identity/keys/rotate` with idempotency key.
- **Emergency rotate**: same with elevated audit severity.
- **Rollback**: `POST /api/admin/identity/keys/{kid}/rollback` never auto-destroys failed key.
- **Destroy**: only when `GET /api/admin/identity/keys/{kid}/safety` is `safe:true` and `ConfirmKid` matches.

## Failure matrix

| Failure | Behavior |
|---------|----------|
| Vault down | Rotation aborts before activation; no signing change. |
| Keycloak down | Stage/activate fails; saga marked Failed; retry. |
| Redis lock held |Concurrent rotate serialized; second caller gets 409. |
| Mid-saga crash | Operation record allows resume; idempotency key returns prior outcome. |
| JWKS not converged | Poll retries until ConvergenceTimeout, then abort. |
