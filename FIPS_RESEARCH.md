# Elasticsearch FIPS 140-2/140-3 Implementation — Deep Reference

> Audience: engineers implementing FIPS support in another Java project.
> Scope: **code-level** enforcement only. Excludes BouncyCastle JAR provisioning,
> `java.security` provider configuration, Gradle build wiring, and JVM startup
> flags — assume those are already handled per the Elasticsearch docs.
>
> All paths are relative to the Elasticsearch repository root
> (`/Users/carp/src/elasticsearch`). Line numbers are approximate at the time of
> writing; use them as pointers, not as immutable citations.

---

## Table of Contents

1. [FIPS detection mechanism](#1-fips-detection-mechanism)
2. [Bootstrap checks](#2-bootstrap-checks)
3. [Password hashing restrictions](#3-password-hashing-restrictions)
4. [TLS/SSL restrictions](#4-tlsssl-restrictions)
5. [Authentication realm restrictions](#5-authentication-realm-restrictions)
6. [License restrictions](#6-license-restrictions)
7. [Cryptographic utility classes](#7-cryptographic-utility-classes)
8. [Tokens, API keys, service accounts, node keystore](#8-tokens-api-keys-service-accounts-node-keystore)
9. [Telemetry / audit](#9-telemetry--audit)
10. [Test infrastructure](#10-test-infrastructure)
11. [Notable pitfalls and conventions](#11-notable-pitfalls-and-conventions)
12. [Suggested implementation checklist](#12-suggested-implementation-checklist)

---

## 1. FIPS detection mechanism

Elasticsearch has **two independent switches** — one for the running production
node and one for the test JVM. They are checked separately and mean subtly
different things.

### 1.1 Production runtime — `xpack.security.fips_mode.enabled`

Declared in
`x-pack/plugin/core/src/main/java/org/elasticsearch/xpack/core/XPackSettings.java`:

```java
public static final Setting<Boolean> FIPS_MODE_ENABLED =
    Setting.boolSetting("xpack.security.fips_mode.enabled", false, Property.NodeScope);

public static final Setting<List<String>> FIPS_REQUIRED_PROVIDERS =
    Setting.stringListSetting("xpack.security.fips_mode.required_providers", Property.NodeScope);

public static final Setting<String> PASSWORD_HASHING_ALGORITHM = defaultStoredPasswordHashAlgorithmSetting(
    "xpack.security.authc.password_hashing.algorithm",
    (s) -> XPackSettings.FIPS_MODE_ENABLED.get(s) ? Hasher.PBKDF2_STRETCH.name() : Hasher.BCRYPT.name());

public static final Setting<String> SERVICE_TOKEN_HASHING_ALGORITHM = defaultStoredPasswordHashAlgorithmSetting(
    "xpack.security.authc.service_token_hashing.algorithm",
    (s) -> Hasher.PBKDF2_STRETCH.name());
```

Two things to notice:

- The **default password hashing algorithm swaps** based on the FIPS switch
  (`PBKDF2_STRETCH` under FIPS, `BCRYPT` otherwise). This is a settings-factory
  trick — the *default value* is a `Function<Settings, String>`, so it re-reads
  the FIPS flag at resolution time.
- The `defaultStoredPasswordHashAlgorithmSetting` /
  `defaultStoredSecureTokenHashAlgorithmSetting` factories install a validator
  that:
  - Restricts values to what `Hasher.getAvailableAlgoStoredPasswordHash()` /
    `getAvailableAlgoStoredSecureTokenHash()` returns.
  - Probes `SecretKeyFactory.getInstance("PBKDF2withHMACSHA512")` on startup and
    throws if the FIPS provider does not export it.

`FIPS_MODE_ENABLED` is consumed by (non-exhaustive):

- `Security.validateForFips(Settings)` — startup validation
- `Security.ValidateLicenseForFIPS` — cluster-join validator
- `KeyStoreWrapper`, `TokenService`, `ApiKeyService` — hashing defaults
- `UsersTool` (CLI) — password algorithm rejection
- `SecurityUsageTransportAction` — telemetry
- `ClusterStateLicenseService` — license installation

### 1.2 Test-time runtime — `tests.fips.enabled`

`test/framework/src/main/java/org/elasticsearch/test/ESTestCase.java`:

```java
public static final String FIPS_SYSPROP = "tests.fips.enabled";

public static boolean inFipsJvm() {
    return Booleans.parseBoolean(System.getProperty(FIPS_SYSPROP, "false"));
}
```

`inFipsJvm()` is called from ~300 test files to:

1. Skip incompatible tests via `assumeFalse(...)`.
2. Pick FIPS-safe algorithms.
3. Select `TLSv1.2` where TLSv1.3 fails on BCJSSE.
4. Apply the 14-character password minimum in test fixtures.

There is also a class-level rule in
`test/framework/src/main/java/org/elasticsearch/test/SkipInFIPSMode.java` — a
JUnit `TestRule` that throws `AssumptionViolatedException` when
`tests.fips.enabled=true`.

### 1.3 Startup entry point — `Security.validateForFips`

`x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/Security.java`:

```java
static void runStartupChecks(Settings settings) {
    if (XPackSettings.FIPS_MODE_ENABLED.get(settings)) {
        validateForFips(settings);
    }
}
```

`validateForFips(Settings)` walks these categories and either throws
`IllegalArgumentException` (fatal) or logs a warning:

| Category                                             | On mismatch |
| ---------------------------------------------------- | ----------- |
| Keystore paths (implicit or explicit `type=jks`)     | **fatal**   |
| `xpack.security.authc.password_hashing.algorithm`    | **fatal**   |
| `xpack.security.authc.service_token_hashing.algorithm` (non-`pbkdf2*`) | warn |
| `xpack.security.authc.api_key.hashing.algorithm` (non-`pbkdf2*`/`ssha256`) | warn |
| `*.cache.hash_algo` (non-`ssha256`/`pbkdf2*`)        | warn        |
| `FIPS_REQUIRED_PROVIDERS` missing                    | **fatal**   |

The provider check supports **version globs** via `SecurityProvider.test()`
— e.g. `BCFIPS:2.0.*`.

---

## 2. Bootstrap checks

Registered by `Security.getBootstrapChecks()`. None are named "FIPS" per se, but
several are relevant when running in FIPS mode.

- **`EncryptSensitiveDataBootstrapCheck`**
  `x-pack/plugin/watcher/src/main/java/org/elasticsearch/xpack/watcher/EncryptSensitiveDataBootstrapCheck.java`
  — requires the Watcher encryption key be in the secure keystore
  (`WatcherField.ENCRYPTION_KEY_SETTING`), not on disk.
  `alwaysEnforce()` returns `true` — it runs even in dev mode. Failure message
  links to `ReferenceDocs.BOOTSTRAP_CHECK_ENCRYPT_SENSITIVE_DATA`.
- **`TokenSSLBootstrapCheck`** — enforces `xpack.security.http.ssl.enabled=true`
  when the token service is on.
- **`PkiRealmBootstrapCheck`** — HTTP layer must require or optionally accept
  client certs when a PKI realm is defined.
- **`TransportTLSBootstrapCheck`** — transport-layer TLS mandatory.
- **`RoleMappingFileBootstrapCheck`** — added per LDAP/AD/PKI realm in
  `InternalRealms.getBootstrapChecks`
  (`x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/authc/InternalRealms.java`).

Behavior on failure: node startup aborts if `alwaysEnforce()` returns true or
the node is running in production mode.

---

## 3. Password hashing restrictions

### 3.1 The `Hasher` enum

`x-pack/plugin/core/src/main/java/org/elasticsearch/xpack/core/security/authc/support/Hasher.java`.

Key constants:

```java
private static final int PBKDF2_KEY_LENGTH = 256;
private static final int PBKDF2_DEFAULT_COST = 10000;
private static final int HMAC_SHA512_BLOCK_SIZE_IN_BITS = 128;
private static final int PBKDF2_MIN_SALT_LENGTH_IN_BYTES = 8;
```

Variants:

- `BCRYPT4`..`BCRYPT14` (log-rounds 4→14)
- `PBKDF2`, `PBKDF2_1000`..`PBKDF2_1000000`
- `PBKDF2_STRETCH`, `PBKDF2_STRETCH_1000`..`PBKDF2_STRETCH_1000000`
- `SHA1`, `MD5`, `SSHA256`, `SHA256`, `NOOP`

**Selector methods** used by the settings factory:

```java
public static List<String> getAvailableAlgoStoredPasswordHash() {
    // Only "pbkdf2*" and "bcrypt*" values
}
public static List<String> getAvailableAlgoStoredSecureTokenHash() {
    // Only "pbkdf2*" values
}
public static List<String> getAvailableAlgoCacheHash() {
    // "pbkdf2*" and "ssha256"
}
```

**BC-FIPS defence pattern** — the PBKDF2 hashing methods catch **`Error`**, not
just `Exception`, because BCFIPS throws `java.lang.Error` subclasses when
preconditions fail (short password, short salt, weak IV, disallowed algorithm):

```java
try {
    return "..." + hash(...);
} catch (NoSuchAlgorithmException | InvalidKeySpecException | Error e) {
    throw new ElasticsearchException("...", e);
}
```

The **14-character (112-bit) minimum** password requirement in FIPS mode is not
enforced by Elasticsearch code — it is enforced by BCFIPS itself and surfaces as
the caught `Error`.

### 3.2 `PBKDF2_STRETCH`

Pre-hashes the password with SHA-512 before PBKDF2. This makes brute-forcing
uniform regardless of input length. It is the default for both
`xpack.security.authc.password_hashing.algorithm` and
`xpack.security.authc.service_token_hashing.algorithm` in FIPS.

### 3.3 CLI: `UsersTool`

`x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/authc/file/tool/UsersTool.java`
rejects non-`pbkdf2*` password hashing when FIPS is enabled — mirrors runtime
behavior at the CLI layer.

### 3.4 Test evidence

`x-pack/plugin/security/src/test/java/org/elasticsearch/xpack/security/authc/support/HasherTests.java`:

- Comment: *"In FIPS 140 mode, passwords for PBKDF2 need to be at least 14 chars (112 bits)"*
- `testPbkdf2WithShortPasswordThrowsInFips` — 13-char password → `ElasticsearchException`.
- Under `inFipsJvm()` tests generate ≥14-char passwords or `assumeFalse`.

---

## 4. TLS/SSL restrictions

### 4.1 `TrustEverythingConfig` is forbidden in FIPS

`libs/ssl-config/src/main/java/org/elasticsearch/common/ssl/TrustEverythingConfig.java`
class Javadoc explicitly says:

> *"This class cannot be used on FIPS-140 JVM as it has its own trust manager implementation."*

That backs `xpack.security.transport.ssl.verification_mode: none` — that setting
is effectively unavailable in FIPS.

### 4.2 Keystore type inference — implicit JKS rejected

`libs/ssl-config/src/main/java/org/elasticsearch/common/ssl/KeyStoreUtil.java`:

```java
public static String inferKeyStoreType(String path) {
    if (path == null) return "PKCS12";
    String p = path.toLowerCase(Locale.ROOT);
    if (p.endsWith(".p12") || p.endsWith(".pfx") || p.endsWith(".pkcs12")) return "PKCS12";
    return "jks";
}
```

`Security.validateForFips` walks every `xpack.*.ssl.keystore.path` /
`truststore.path`, calls `inferKeyStoreType`, and **rejects `"jks"`**. Explicit
`keystore.type=jks` is also rejected.

Under FIPS the compliant keystore format is **BCFKS** — tests set:

```yaml
xpack.security.transport.ssl.keystore.type: BCFKS
```

### 4.3 PBES2 handling on BCFIPS

`libs/ssl-config/src/main/java/org/elasticsearch/common/ssl/PemUtils.java`:

```java
// BCFIPS does not support the PBES2Parameters spec, so AlgorithmParameters may be null.
private static String getPBES2Algorithm(ASN1ObjectIdentifier oid, AlgorithmParameters params) {
    if (params == null) {
        return oid.getId();
    }
    ...
}
```

Any code parsing encrypted PKCS#8 keys must fall back to the OID from the
ASN.1 structure when `AlgorithmParameters` is null.

### 4.4 TLS protocol version

BCJSSE historically has TLS 1.3 rough edges. Internal-cluster tests pin
TLSv1.2 under FIPS:

`x-pack/plugin/security/src/internalClusterTest/java/org/elasticsearch/xpack/ssl/SslClientAuthenticationTests.java`:

```java
SSLContext sslContext = SSLContext.getInstance(
    inFipsJvm() ? "TLSv1.2" : randomFrom("TLSv1.3", "TLSv1.2"));
```

`x-pack/plugin/core/src/test/java/org/elasticsearch/xpack/core/XPackSettingsTests.java`
asserts that when FIPS is on, `SSLContext.getInstance("TLSv1.2")` resolves via
provider **`BCJSSE`**:

```java
assertEquals("BCJSSE", provider.getName());
```

### 4.5 REST test framework accommodations

`test/framework/src/main/java/org/elasticsearch/test/rest/ESRestTestCase.java`
— when `inFipsJvm()`:

- Rejects a `truststore` path (only PEM CAs allowed) with a helpful error.
- Appends `"secure_settings_password": FIPS_KEYSTORE_PASSWORD` to
  `_nodes/reload_secure_settings` requests so the FIPS-protected keystore can
  be re-read.

---

## 5. Authentication realm restrictions

### 5.1 SAML — RSA v1.5 disallowed

`x-pack/plugin/security/src/test/java/org/elasticsearch/xpack/security/authc/saml/SamlAuthenticatorTests.java`
comment:

> *"RSA v1.5 is not allowed when running in FIPS mode"*

Only **RSA-OAEP** is accepted. For encrypted SAML assertions the key-transport
algorithm must be `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` (or newer),
never `http://www.w3.org/2001/04/xmlenc#rsa-1_5`. Enforcement flows through
OpenSAML/xmlsec riding on BCFIPS.

### 5.2 OIDC / JWT

The realms use `com.nimbusds` JOSE, which under BCFIPS excludes:

- HMAC keys shorter than the digest length (HS256 requires ≥256-bit secret).
- RSA keys below 2048 bits.
- All non-approved algorithms (`none`, `RSA1_5` for JWE key wrap, etc.).

There is **no dedicated FIPS switch** in the OIDC/JWT realms — enforcement
bubbles up from BCFIPS as `InvalidKeyException` / `Error` and surfaces as an
authentication failure.

### 5.3 PKI

`PkiRealmBootstrapCheck` requires client-auth on the HTTP layer. Trust material
must load via BCFKS or PEM CAs — the JKS rejection in `validateForFips`
applies.

### 5.4 LDAP / AD

TLS to the directory uses the same SSL config plumbing → BCFKS/PEM required,
JKS forbidden.

### 5.5 Enrollment — unsupported

Multiple tests assume FIPS-off because enrollment uses PKCS#12:

- `EnrollmentSingleNodeTests`
- `ExternalEnrollmentTokenGeneratorTests`
- `InternalEnrollmentTokenGeneratorTests`
- `TransportKibanaEnrollmentActionTests`
- `CreateEnrollmentTokenToolTests`

All contain:

```java
assumeFalse("Enrollment is not supported in FIPS 140-2 as we are using PKCS#12 keystores", inFipsJvm());
```

### 5.6 Reserved-realm defaults

`x-pack/plugin/security/src/test/java/org/elasticsearch/xpack/security/authc/esnative/ReservedRealmTests.java`
uses the bootstrap password literal
`"foobar longer than 14 chars because of FIPS"` throughout so PBKDF2
preconditions pass.

---

## 6. License restrictions

### 6.1 Allowed license modes

`x-pack/plugin/core/src/main/java/org/elasticsearch/license/XPackLicenseState.java`:

```java
public static boolean isFipsAllowedForOperationMode(final OperationMode operationMode) {
    return isAllowedByOperationMode(operationMode, OperationMode.PLATINUM);
}
```

`isAllowedByOperationMode(op, PLATINUM)` returns true for **PLATINUM**,
**ENTERPRISE**, and **TRIAL**. Basic / Standard / Gold / Missing return false.

### 6.2 Join validator

`x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/Security.java`
inner class `ValidateLicenseForFIPS`:

```java
throw new IllegalStateException(
    "FIPS mode cannot be used with a [" + mode + "] license. "
  + "It is only allowed with a Platinum or Trial license.");
```

### 6.3 License installation rejection

`x-pack/plugin/core/src/main/java/org/elasticsearch/license/ClusterStateLicenseService.java`:

```java
if (XPackSettings.FIPS_MODE_ENABLED.get(settings)
    && XPackLicenseState.isFipsAllowedForOperationMode(newLicense.operationMode()) == false) {
    throw new IllegalStateException(
        "Cannot install a [" + newLicense.operationMode() + "] license unless FIPS mode is disabled");
}
```

### 6.4 `CryptUtils` — license signature crypto

`x-pack/plugin/core/src/main/java/org/elasticsearch/license/CryptUtils.java`:

- SALT is **128 bits** — comment explicitly cites *"for FIPS 140-2 compliance"*.
- KDF is `PBKDF2WithHmacSHA512`, cipher is `AES` with 128-bit keys.

### 6.5 Tests

`x-pack/plugin/core/src/test/java/org/elasticsearch/license/LicenseFIPSTests.java`
— `testFIPSCheckWithoutAllowedLicense` asserts gold/standard/basic are rejected
under FIPS with the message above.

---

## 7. Cryptographic utility classes

| Class                                              | Role                                                                                     |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `Hasher`                                           | Password hashing enum (see §3)                                                           |
| `KeyStoreWrapper`                                  | Node secure-settings store (see §8.1)                                                    |
| `TokenService`                                     | Bearer token minting/verification (see §8.2)                                             |
| `CryptUtils`                                       | License signature crypto (see §6.4)                                                      |
| `SamlSpConfiguration` / `SamlUtils`                | Resolves XML Signature/Encryption URIs — FIPS-incompatible URIs rejected                 |
| `ESTestCase.secureRandom` / `secureRandomFips`     | `SHA1PRNG/SUN` in normal JVMs; `DEFAULT/BCFIPS` under FIPS                                |
| `PemUtils`                                         | BCFIPS-aware PBES2 parsing (§4.3)                                                        |
| `KeyStoreUtil`                                     | JKS inference driving FIPS validation (§4.2)                                             |
| `TrustEverythingConfig`                            | Explicitly documented as non-FIPS (§4.1)                                                 |

**Convention**: production code universally uses
`SecureRandom.getInstance("DEFAULT")` when a specific algorithm string is
required. This lets BCFIPS return its DRBG when installed and lets non-FIPS
deployments use the platform default.

---

## 8. Tokens, API keys, service accounts, node keystore

### 8.1 `KeyStoreWrapper` — the node's own secure-settings store

`server/src/main/java/org/elasticsearch/common/settings/KeyStoreWrapper.java`:

```java
private static final int KDF_ITERS       = 210_000;
private static final int CIPHER_KEY_BITS = 256;
private static final int GCM_TAG_BITS    = 128;
private static final int GCM_IV_BYTES    = 12;
private static final int SALT_SIZE       = 64;
```

Algorithms: `PBKDF2WithHmacSHA512` for KDF, `AES/GCM/NoPadding` for encryption.

BCFIPS defense: like `Hasher`, `KeyStoreWrapper` catches `Error` around
`deriveKey` and `encrypt`/`decrypt` and rethrows as `SecurityException`.

Tests confirm the 14-char minimum on keystore password:
`KeyStoreWrapperTests.testCreateKeyStoreWithShortPasswordInFips`.

### 8.2 `TokenService`

`x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/authc/TokenService.java`:

```java
private static final int TOKEN_SERVICE_KEY_ITERATIONS     = 100_000;
private static final int TOKENS_ENCRYPTION_KEY_ITERATIONS = 1024;
private static final String KDF_ALGORITHM       = "PBKDF2withHMACSHA512";
private static final int SALT_BYTES             = 32;
private static final int KEY_BYTES              = 64;   // 512-bit material
private static final int IV_BYTES               = 12;
private static final String ENCRYPTION_CIPHER   = "AES/GCM/NoPadding";
```

`computeSecretKey(char[] password, byte[] salt, int iterations)` derives a
128-bit AES key via PBKDF2. `SecureRandom.getInstance("DEFAULT")` selects
BCFIPS' DRBG under FIPS.

### 8.3 `ApiKeyService`

`x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/authc/ApiKeyService.java`:

```java
public static final Setting<String> STORED_HASH_ALGO_SETTING =
    XPackSettings.defaultStoredSecureTokenHashAlgorithmSetting(
        "xpack.security.authc.api_key.hashing.algorithm",
        (s) -> Hasher.SSHA256.name());

public static final Setting<String> CACHE_HASH_ALGO_SETTING =
    Setting.simpleString("xpack.security.authc.api_key.cache.hash_algo",
        Hasher.SSHA256.name(), ...);
```

Default is `SSHA256` — allowed in FIPS per
`getAvailableAlgoStoredSecureTokenHash` / `getAvailableAlgoCacheHash`.
`Security.validateForFips` warns if the configured algo isn't PBKDF2 or
SSHA256.

### 8.4 Service accounts / service tokens

Same rules — service tokens use
`xpack.security.authc.service_token_hashing.algorithm` whose FIPS default is
`PBKDF2_STRETCH`.

---

## 9. Telemetry / audit

### 9.1 Usage telemetry

`x-pack/plugin/security/src/main/java/org/elasticsearch/xpack/security/SecurityUsageTransportAction.java`:

```java
usage.put("fips_140", fips140Usage(settings));

private static Map<String, Object> fips140Usage(Settings settings) {
    return Map.of("enabled", XPackSettings.FIPS_MODE_ENABLED.get(settings));
}
```

### 9.2 Usage XContent

`x-pack/plugin/core/src/main/java/org/elasticsearch/xpack/core/security/SecurityFeatureSetUsage.java`
— writes the `fips_140` field to `_xpack/usage` output.

### 9.3 Audit

There is **no FIPS-specific audit surface**. Audit logs pass through the same
security manager (now the entitlement engine) and JSON logger regardless of
FIPS. Audit shipping over TLS follows the general SSL restrictions.

---

## 10. Test infrastructure

### 10.1 `inFipsJvm()` and `SkipInFIPSMode`

Dominant patterns:

```java
assumeFalse("Reason", inFipsJvm());
```

or class-level:

```java
@Rule public TestRule fipsSkip = new SkipInFIPSMode("Reason");
```

### 10.2 Random algorithm helpers

`ESTestCase.java`:

- `secureRandom(seed)` — `SHA1PRNG/SUN` normally; `DEFAULT/BCFIPS` in FIPS.
- `secureRandomFips(seed)` — always `SecureRandom.getInstance("DEFAULT")`
  (BCFIPS' DRBG when installed).

### 10.3 Cluster configuration

`test/test-clusters/src/main/java/org/elasticsearch/test/cluster/local/FipsEnabledClusterConfigProvider.java`
— under `tests.fips.enabled=true` configures:

- `xpack.security.fips_mode.enabled=true`
- `xpack.license.self_generated.type=trial`
- `xpack.security.authc.password_hashing.algorithm=pbkdf2_stretch`
- `xpack.security.fips_mode.required_providers=[BCFIPS, BCJSSE]`
- BCFKS truststore + keystore password

### 10.4 Fast-hash helper for tests

`x-pack/plugin/security/src/internalClusterTest/java/org/elasticsearch/test/SecuritySingleNodeTestCase.java`:

```java
public static Hasher getFastStoredHashAlgoForTests() {
    return inFipsJvm()
        ? randomFrom(Hasher.PBKDF2, Hasher.PBKDF2_1000, Hasher.PBKDF2_STRETCH_1000, Hasher.PBKDF2_STRETCH)
        : randomFrom(Hasher.BCRYPT4, Hasher.BCRYPT5, Hasher.PBKDF2, Hasher.PBKDF2_1000, ...);
}
```

### 10.5 Provider verification test

`x-pack/plugin/core/src/test/java/org/elasticsearch/xpack/core/Fips140ProviderVerificationTests.java`:

```java
public void testBcFipsProviderInUse() {
    if (inFipsJvm()) {
        assertThat(Security.getProviders()[0].getName(), containsString("BCFIPS"));
    }
}

public void testInApprovedOnlyMode() {
    if (inFipsJvm()) {
        assertThat(CryptoServicesRegistrar.isInApprovedOnlyMode(), equalTo(true));
    }
}
```

Confirms BCFIPS is the **first** (default) provider and BCFIPS is running in
**approved-only mode**.

### 10.6 Validation tests

`x-pack/plugin/security/src/test/java/org/elasticsearch/xpack/security/SecurityTests.java`
— `testValidateForFips*` methods verify:

- JKS keystore path (implicit or `type=jks`) throws.
- Non-`pbkdf2*` password hashing throws.
- Non-compliant service-token / api-key / cache hash logs a warning.
- `SecurityProvider.test()` matches version globs like `BCFIPS:2.0.*`.

`XPackSettingsTests.java` — `testDefaultPasswordHashingAlgorithmInFips`,
`testDefaultSupportedProtocols`, `testServiceTokenHashingAlgorithmSettingValidation`,
`testDefaultServiceTokenHashingAlgorithm`.

---

## 11. Notable pitfalls and conventions

### 11.1 Entitlements policy grants FIPS-specific permissions

`libs/entitlement/src/main/java/org/elasticsearch/entitlement/bootstrap/HardcodedEntitlements.java`
— when `org.bouncycastle.fips.approved_only=true`, extra entitlements are
granted:

- `org.bouncycastle.fips.tls` — trust store read + network access
- `org.bouncycastle.fips.core` — library read

Elasticsearch's entitlement engine (its replacement for the removed JVM
`SecurityManager`) needs these carve-outs because BCFIPS self-tests on load and
reads files under the JVM install.

### 11.2 BCFIPS throws `java.lang.Error`, not `Exception`

`Hasher`, `KeyStoreWrapper`, `TokenService` all explicitly catch `Error`
because BCFIPS' approved-only guardrails throw subclasses of `java.lang.Error`
on precondition failures (short password, short salt, weak IV, disallowed
algorithm).

**Any Java project targeting FIPS must adopt this pattern** or risk unhandled
`Error` propagation.

### 11.3 BCFIPS approved-only mode has no PBES2 spec support

`PemUtils.getPBES2Algorithm` explicitly handles `AlgorithmParameters == null` —
BCFIPS returns null instead of a filled-in `PBES2Parameters`. Code parsing
encrypted PKCS#8 keys must fall back to the OID from the ASN.1 structure.

### 11.4 Provider matching supports version globs

`Security.validateForFips` uses `SecurityProvider.test()` accepting entries
like `BCFIPS:2.0.*` — the `name:versionGlob` syntax lets deployments pin to a
certified provider version.

### 11.5 Reload secure-settings requires the keystore password

`ESRestTestCase` automatically appends `"secure_settings_password"` to
`_nodes/reload_secure_settings` calls under FIPS. Any REST client library used
against a FIPS ES node must expose this parameter.

### 11.6 TLS 1.3 pitfalls in BCJSSE

BCJSSE historically had issues with some TLS 1.3 features (session resumption,
0-RTT). Internal-cluster tests pin `TLSv1.2` under FIPS. If your project
targets TLS 1.3, verify the BCJSSE build in use passes your interop matrix.

### 11.7 Encrypted-sensitive-data key must be in the keystore

`EncryptSensitiveDataBootstrapCheck` refuses to start if
`xpack.watcher.encrypt_sensitive_data=true` and the encryption key is a
`system_key` file on disk instead of an entry in the FIPS-protected keystore.
`alwaysEnforce()` is true — this applies even outside FIPS but is especially
relevant in FIPS deployments.

### 11.8 Enrollment feature is off-limits

Enrollment (auto-bootstrap trust between a new node/Kibana and the cluster)
uses PKCS#12 and is unsupported in FIPS. Plan an alternative provisioning
flow.

### 11.9 Salts and IVs sized for approved-only

Everywhere (`KeyStoreWrapper`, `TokenService`, `Hasher`, `CryptUtils`):

- Salts ≥ **128 bits**
- IVs = **96 bits** (12 bytes) for GCM

These match BCFIPS' minimum precondition thresholds. Any port must not use
shorter values.

### 11.10 `SecureRandom.getInstance("DEFAULT")` is the FIPS-safe idiom

Elasticsearch avoids naming a specific PRNG algorithm in production code paths.
Requesting `"DEFAULT"` lets BCFIPS return its DRBG when installed and lets
non-FIPS deployments use the platform default.

### 11.11 Documentation reference wiring

`ReferenceDocs.BOOTSTRAP_CHECK_ENCRYPT_SENSITIVE_DATA` (and similar) are wired
into bootstrap check failure messages so operators land on the correct docs
page — a nice pattern to mimic for user-facing errors.

---

## 12. Suggested implementation checklist

For a Java project adopting FIPS:

1. **Introduce a single `fips_mode.enabled` setting** plus a
   `fips_mode.required_providers` list (with `name:versionGlob` support).
2. **Introduce a `tests.fips.enabled` system property** and a shared
   `inFipsJvm()` helper on the base test case.
3. **Split password hashing behind an enum**; gate defaults on FIPS to
   PBKDF2/PBKDF2_STRETCH; always `catch (Error)` around BCFIPS calls.
4. **Route every keystore path through a util that rejects JKS** in FIPS
   (implicit or explicit).
5. **Ban a `TrustEverything`/`verification_mode=none` code path** under FIPS,
   or throw at load time.
6. **Centralize entropy on `SecureRandom.getInstance("DEFAULT")`** — never
   `SHA1PRNG`, `NativePRNG`, or a named DRBG in production paths.
7. **Add a startup `validateForFips(Settings)`** that:
   - Rejects JKS (implicit and explicit)
   - Forbids non-PBKDF2 stored passwords
   - Warns on non-approved auxiliary hashes (service tokens, API keys, caches)
   - Validates required providers with `name:versionGlob`
8. **Add bootstrap checks** for secure-storage of any encryption keys and for
   TLS being enabled where required.
9. **Add license/tier gating** if applicable (Elasticsearch requires
   Platinum/Enterprise/Trial).
10. **Provide a JUnit `SkipInFIPSMode` rule + `assumeFalse(inFipsJvm())`
    idiom** for tests.
11. **Add a self-test class** asserting the first provider is BCFIPS and
    `CryptoServicesRegistrar.isInApprovedOnlyMode()` is true.
12. **Ship telemetry** exposing `fips_140.enabled` for observability.
13. **Salt ≥128 bits, IV = 96 bits for GCM, AES-256** — do not use smaller
    values anywhere.
14. **Reject enrollment / PKCS#12-only flows** or provide a BCFKS alternative.
15. **For SAML/OIDC/JWT**: rely on BCFIPS to enforce approved algorithms, but
    surface useful errors (test the error paths explicitly).
16. **For encrypted PEM**: handle `AlgorithmParameters == null` from
    `AlgorithmParameters.getInstance("PBES2")` — fall back to the ASN.1 OID.

---

## Appendix — one-line lookup table

| Question                                                     | Answer                                                                 |
| ------------------------------------------------------------ | ---------------------------------------------------------------------- |
| How does code know FIPS is on?                               | `XPackSettings.FIPS_MODE_ENABLED.get(settings)` (prod) / `inFipsJvm()` (tests) |
| Default password algorithm in FIPS                           | `PBKDF2_STRETCH`                                                       |
| Default service-token algorithm in FIPS                      | `PBKDF2_STRETCH`                                                       |
| Default API-key stored-hash algorithm                        | `SSHA256` (allowed in FIPS)                                            |
| Default API-key cache-hash algorithm                         | `SSHA256`                                                              |
| Allowed keystore types                                       | BCFKS, PKCS12 for keys not requiring FIPS storage; **JKS forbidden**   |
| Minimum password length in FIPS                              | 14 chars / 112 bits (enforced by BCFIPS, surfaces as `Error`)          |
| Salt size                                                    | ≥128 bits everywhere                                                   |
| GCM IV                                                       | 96 bits (12 bytes)                                                     |
| KDF                                                          | `PBKDF2WithHmacSHA512`, 100k–210k iterations                           |
| Symmetric cipher                                             | `AES/GCM/NoPadding`, 128- or 256-bit keys                              |
| Allowed licenses in FIPS                                     | Platinum, Enterprise, Trial                                            |
| TLS version pinned in tests                                  | TLSv1.2 under FIPS                                                     |
| TLS provider under FIPS                                      | BCJSSE                                                                 |
| SAML key transport                                           | RSA-OAEP only (RSA v1.5 forbidden)                                     |
| Enrollment                                                   | **Not supported** in FIPS                                              |
| `SecureRandom` algorithm string                              | `"DEFAULT"`                                                            |
| Exceptions to catch around crypto                            | `NoSuchAlgorithmException`, `InvalidKeySpecException`, **`Error`**     |

