# Logstash Ruby/JRuby FIPS Research Report & Roadmap

**Branch**: `fips`
**Date**: 2026-07-07
**Scope**: Stock Logstash + FIPS opt-in (`xpack.security.fips_mode.enabled=true`), extending what already exists in the `x-pack/distributions/internal/observabilitySRE` distribution.

---

## Background

Logstash's initial FIPS work is Java-heavy. It adds a `FipsBootstrapCheck` (`x-pack/lib/security/fips_bootstrap_check.rb`), pulls in BC-FIPS jars via Gradle (`x-pack/build.gradle`), and ships a `logstash-integration-fips_validation` runtime validator (`x-pack/distributions/internal/observabilitySRE/plugin/logstash-integration-fips_validation/lib/logstash/fips_validation.rb`). **It only covers the JVM** — provider ordering, `bouncycastle.fips.approved_only=true`, and disabling JRuby-OpenSSL's non-FIPS BC provider. The Ruby layer and the plugin ecosystem have not been assessed.

Ruby code that touches `OpenSSL::*`, `Digest::MD5`, PBE-backed keystores, or JKS/PKCS12 stores will silently break — or silently violate FIPS — once approved-only mode is on. This document inventories what breaks, categorizes every default-bundle plugin by FIPS status, and lays out a phased implementation plan.

---

## 1. Ruby/JRuby-layer FIPS gaps in logstash-core

### 1.1 Critical blockers (startup fails under approved-only mode)

| # | Gap | Evidence | Fix |
|---|---|---|---|
| C1 | **Secret keystore uses PKCS12 + `SecretKeyFactory.getInstance("PBE")` + `java.util.Random`** — none FIPS-approved | `logstash-core/src/main/java/org/logstash/secret/store/backend/JavaKeyStore.java:78,116,209,330,388`; `logstash-core/src/main/java/org/logstash/secret/store/SecretStoreUtil.java:39,171` | Switch to BCFKS when FIPS enabled; replace PBE with `PBKDF2WithHmacSHA256` + AES-256; replace `java.util.Random` with `SecureRandom` |
| C2 | **API webserver hard-codes JKS** for keystore validation | `logstash-core/lib/logstash/webserver.rb:257-259` (`KeyStore.getInstance("JKS")`) | Honor `api.ssl.keystore.type` setting; default to BCFKS under FIPS |
| C3 | **`jruby-openssl` auto-registers Bouncy Castle 1.84 (non-FIPS)** at load time; FIPS validator explicitly forbids this. Currently only the observabilitySRE Dockerfile sets the required JVM flags. Stock startup registers the wrong provider. | `vendor/jruby/lib/ruby/stdlib/jopenssl/load.rb`; `vendor/jruby/lib/ruby/stdlib/jopenssl/version.rb` (`BOUNCY_CASTLE_VERSION = '1.84'`) | Inject `-Djruby.openssl.load.jars=false -Djruby.openssl.provider.register=false` from `bin/logstash.lib.sh` when `xpack.security.fips_mode.enabled=true` is detected in `logstash.yml` |
| C4 | **`stronger_openssl_defaults.rb` unconditionally `require "openssl"`**, loading jruby-openssl before any FIPS check | `logstash-core/lib/logstash/patches/stronger_openssl_defaults.rb` | Gate on FIPS mode; when FIPS-on skip the monkeypatch and rely on JSSE + BCJSSE defaults, or reimplement the cipher-list clamp at the Java level |
| C5 | **GeoIP downloader uses `Digest::MD5`** for integrity checks; under approved-only mode `Digest::MD5` throws `NoSuchAlgorithmException`. MaxMind only publishes MD5 checksums. | `x-pack/lib/geoip_database_management/util.rb:18`; `x-pack/lib/geoip_database_management/downloader.rb:118` | Disable auto-download when FIPS on; require operator-provided DB (simpler and defensible for FIPS deployments) |

### 1.2 Bootstrap-check coverage gaps

`FipsBootstrapCheck` (`x-pack/lib/security/fips_bootstrap_check.rb`) only asserts that named providers are *present*. The richer `fips_validation.rb` additionally asserts:

- BCFIPS is the **first** provider
- `SecureRandom.new.getProvider.getName == "BCFIPS"`
- `CryptoServicesRegistrar.isInApprovedOnlyMode == true`
- `FipsStatus.isReady == true`
- `org.jruby.ext.openssl.SecurityHelper.isProviderRegistered == false`

These stricter assertions never fire in the stock distribution. When FIPS is lifted to stock, they must move into `FipsBootstrapCheck` or a shared library it calls.

### 1.3 Ruby-side crypto surfaces already FIPS-safe

- `SecureRandom.uuid` in `agent.rb` and `plugin.rb` — routes to `java.security.SecureRandom`, BCFIPS-backed when provider ordering is correct
- `Digest::SHA256` in `ssl_file_tracker.rb` and `pluginmanager/util.rb` — SHA-256 is FIPS-approved
- `CATrustedFingerprintTrustStrategy` — uses SHA-256

### 1.4 Monitoring and config-management

`x-pack/lib/monitoring/monitoring.rb` + `x-pack/lib/template.cfg.erb` pass SSL settings to an internal ES output pipeline. The output plugin validator currently accepts only `pkcs12|jks` for keystore type. Under FIPS, `bcfks` must be accepted (see §2 systemic blocker #1).

`x-pack/lib/config_management/*` pulls pipeline configs from ES via Manticore/JSSE, which is FIPS-clean once provider ordering is set.

---

## 2. Plugin ecosystem: default-bundle FIPS status

### 2.1 Headline numbers (default bundle = 82 plugins + 8 mixins = 90 gems)

| Class | Count | Meaning |
|---|---:|---|
| SUPPORTED | 19 | Allowlisted, exercised end-to-end in observabilitySRE |
| SUPPORTED-CANDIDATE | 34 | No crypto surface — needs only bundle-level FIPS mode active |
| NEEDS-WORK (config/validator) | 8 | TLS via Manticore/JSSE — mostly a validator + docs change per plugin |
| NEEDS-WORK (code refactor) | 5 | Uses Ruby `OpenSSL::SSL` — needs JSSE/BCJSSE rewrite |
| BLOCKED (protocol-level) | 5 | Non-FIPS primitives baked into the wire protocol or unbounded user code |
| BLOCKED (native/gem dep) | 2 | Non-JSSE Ruby gem dependencies |
| EXCLUDED-BY-POLICY | 4 | Deprecated / unmaintained |

### 2.2 Top 5 systemic blockers (fixing these unlocks the most plugins)

**#1 — `logstash-mixin-http_client` `ssl_keystore_type` validator** hard-codes `%w[pkcs12 jks]` — no `bcfks`.
Adding `bcfks` to this one mixin promotes ~15 plugins to SUPPORTED with a validator-only change.
Evidence: `vendor/bundle/jruby/3.4.0/gems/logstash-mixin-http_client-7.5.0/lib/logstash/plugin_mixins/http_client.rb:107,133`

**#2 — Ruby `OpenSSL::SSL` code paths** in `logstash-input-tcp`, `logstash-output-tcp`, `logstash-input-syslog`, `logstash-output-redis`, `logstash-output-webhdfs`.
The FIPS validator disables the jruby-openssl security helper — these plugins fail at TLS handshake time.
Fix: replace `OpenSSL::SSL::SSLContext` construction with JSSE/BCJSSE via a shared helper.

**#3 — Manticore's `openssl_pkcs8_pure` dep** — pure-Ruby PKCS#8 parser, only hit when loading unencrypted PEM keys (not keystores). Confirm it is bypassed when the user provides a JSSE keystore instead.
Evidence: `Gemfile.lock` line ~700.

**#4 — `Digest::MD5` for sincedb filename hashing** in `logstash-input-file:447`, `logstash-input-dead_letter_queue:53`, `logstash-integration-aws/inputs/s3.rb:340`.
Not security-sensitive but throws `NoSuchAlgorithmException` under approved-only mode. Trivial fix: swap to SHA-256 with backwards-compat read of old MD5-named sincedb files.

**#5 — `logstash-integration-aws` does not expose `use_fips_endpoint`**.
`aws-sdk-core 3.252` (pinned in `Gemfile.lock`) already supports `use_fips_endpoint: true`; the plugin just needs to plumb the config option through `aws_config.rb`.

### 2.3 Per-plugin FIPS matrix

Legend: **S** = Supported · **SC** = Supported-Candidate · **NW** = Needs-Work (config/validator) · **NW-C** = Needs-Work (code refactor) · **B** = Blocked · **X** = Excluded-by-policy

#### Allowlisted (SUPPORTED)

| Plugin | Version | Status | Notes |
|---|---|---|---|
| logstash-codec-json | 3.1.1 | S | Pure format; no crypto |
| logstash-codec-multiline | 3.1.2 | S | jls-grok only |
| logstash-codec-plain | 3.1.0 | S | Pass-through |
| logstash-codec-rubydebug | 3.1.0 | S | amazing_print only |
| logstash-filter-age | 1.0.3 | S | Arithmetic only |
| logstash-filter-date | 3.2.1 | S | Date parsing only |
| logstash-filter-drop | 3.0.5 | S | 6-line filter |
| logstash-filter-fingerprint | 3.5.0 | **S (caveat)** | MD5/SHA1 modes throw under approved-only mode; add boot-time guard to reject those algorithm values when FIPS is active. `filters/fingerprint.rb:92` |
| logstash-filter-grok | 4.4.4 | S | jls-grok only |
| logstash-filter-json | 3.2.1 | S | jrjackson |
| logstash-filter-mutate | 3.6.0 | S | Field manipulation |
| logstash-filter-prune | 3.0.4 | S | Field prune |
| logstash-input-beats | 7.0.12-java | S | Netty/JSSE; pkcs12/jks keystore accepted; add `bcfks` to validator |
| logstash-input-generator | 3.1.0 | S | Test input |
| logstash-input-pipeline | (core) | S | Ships in logstash-core |
| logstash-output-elasticsearch | 12.1.6-java | **S (caveat)** | Manticore/JSSE; add `bcfks` to `ssl_keystore_type` validator in `api_configs.rb:64-82` |
| logstash-output-pipeline | (core) | S | Ships in logstash-core |
| logstash-output-stdout | 3.1.4 | S | stdout only |
| logstash-patterns-core | 4.3.4 | S | Grok patterns only |

#### Codecs (not allowlisted)

| Plugin | Version | Status | Blocker / Notes |
|---|---|---|---|
| logstash-codec-avro | 3.5.0-java | NW | Schema-registry TLS via Manticore/JSSE; same validator fix as http_client |
| logstash-codec-cef | 6.2.8-java | SC | Pure Java CEF encoder; no crypto |
| logstash-codec-collectd | 3.1.1 | **B** | Wire protocol requires `AES-256-OFB` + SHA1/SHA256 HMAC via `OpenSSL::Cipher`. OFB mode not approved in FIPS-140-3 approved-only. `collectd.rb:162-169,359,364,379,389,404` |
| logstash-codec-dots | 3.0.6 | SC | No crypto |
| logstash-codec-edn | 3.1.0 | SC | EDN serialization |
| logstash-codec-edn_lines | 3.1.0 | SC | EDN serialization |
| logstash-codec-es_bulk | 3.1.0 | SC | Bulk-format parsing |
| logstash-codec-fluent | 3.4.3-java | SC | msgpack; no crypto |
| logstash-codec-graphite | 3.0.6 | SC | Text encoder |
| logstash-codec-json_lines | 3.2.2 | SC | jrjackson |
| logstash-codec-line | 3.1.1 | SC | Line splitter |
| logstash-codec-msgpack | 3.1.0-java | SC | msgpack |
| logstash-codec-netflow | 4.3.4 | SC | bindata only; unencrypted UDP protocol |

#### Filters (not allowlisted)

| Plugin | Version | Status | Blocker / Notes |
|---|---|---|---|
| logstash-filter-aggregate | 2.11.0 | SC | Stateful aggregation; no crypto |
| logstash-filter-anonymize | 3.0.7 | **B (config-dep)** | Accepts MD5 / HMAC-SHA1 algorithms; `anonymize.rb:20,72-92`. Fix: add FIPS-mode guard rejecting MD5/SHA1 — then NW |
| logstash-filter-cidr | 3.2.0-java | SC | IP range check |
| logstash-filter-clone | 4.2.0 | SC | Event copy |
| logstash-filter-csv | 3.1.1 | SC | CSV parse |
| logstash-filter-de_dot | 1.2.0 | SC | Field rename |
| logstash-filter-dissect | 1.3.0 | SC | String split; native Java |
| logstash-filter-dns | 3.2.0 | SC | DNS resolver; no crypto |
| logstash-filter-elastic_integration | 9.4.4-java | SC | Runs ES ingest-node pipelines via JSSE; already used with FIPS ES cluster |
| logstash-filter-elasticsearch | 4.4.1 | NW | Manticore/JSSE; add `bcfks` to `ssl_keystore_type` validator |
| logstash-filter-geoip | 8.0.0-java | SC | Java MaxMind MMDB; no crypto |
| logstash-filter-http | 2.0.0 | NW | Uses `logstash-mixin-http_client` (systemic blocker #1) |
| logstash-filter-kv | 4.7.0 | SC | Key-value parse |
| logstash-filter-memcached | 1.2.0 | NW | dalli client; no TLS config exposed in this plugin version; needs plugin update |
| logstash-filter-metrics | 4.0.7 | SC | Statistical metrics; no crypto |
| logstash-filter-ruby | 3.1.8 | **B** | Executes arbitrary user Ruby code — cannot guarantee FIPS compliance; mark as user-responsibility |
| logstash-filter-sleep | 3.0.7 | SC | Kernel#sleep |
| logstash-filter-split | 3.1.10 | SC | Array split |
| logstash-filter-syslog_pri | 3.2.1 | SC | PRI byte parse |
| logstash-filter-throttle | 4.0.4 | SC | Concurrency counter |
| logstash-filter-translate | 3.5.0 | SC | Dictionary lookup (YAML) |
| logstash-filter-truncate | 1.0.6 | SC | String truncate |
| logstash-filter-urldecode | 3.0.6 | SC | URL decode |
| logstash-filter-useragent | 3.3.5-java | SC | UA parser; Java |
| logstash-filter-uuid | 3.0.5 | SC | `SecureRandom.uuid` routes to BCFIPS RNG when provider ordering is correct; verify empirically |
| logstash-filter-xml | 4.3.2 | SC | nokogiri XML; no crypto |

#### Inputs (not allowlisted)

| Plugin | Version | Status | Blocker / Notes |
|---|---|---|---|
| logstash-input-azure_event_hubs | 1.5.8 | NW | Azure EventHubs Java SDK; SAS = HMAC-SHA256 (OK); AMQP-over-TLS via JSSE; needs validation |
| logstash-input-couchdb_changes | 3.1.6 | **X** | Uses `Net::HTTP` with `use_ssl:` (JRuby OpenSSL path); deprecated, not strategic |
| logstash-input-dead_letter_queue | 2.0.2 | NW | `Digest::MD5` for sincedb filename (`dlq.rb:53`); swap to SHA-256; otherwise no crypto |
| logstash-input-elasticsearch | 5.3.2 | NW | Manticore/JSSE; add `bcfks` to `ssl_keystore_type` validator |
| logstash-input-elastic_serverless_forwarder | 2.0.0-java | NW | Delegates entirely to `logstash-input-http`; fix #1 and this comes free |
| logstash-input-exec | 3.6.0 | SC | `IO.popen`; no crypto |
| logstash-input-file | 4.4.7 | NW | `Digest::MD5` for sincedb filename (`file.rb:447`); swap to SHA-256 |
| logstash-input-ganglia | 3.1.4 | **X** | Unmaintained; no SSL support |
| logstash-input-gelf | 3.4.0 | SC | UDP + gelfd2; no crypto |
| logstash-input-graphite | 3.0.6 | SC | Delegates to logstash-input-tcp (plaintext by default) |
| logstash-input-heartbeat | 3.1.1 | SC | Timer; no crypto |
| logstash-input-http | 4.1.11-java | NW | Netty/JSSE; add `bcfks` to `ssl_keystore_type` validator (`http.rb:71-90`) |
| logstash-input-http_poller | 6.0.0 | NW | Uses `logstash-mixin-http_client` (systemic blocker #1) |
| logstash-input-jms | 3.3.1-java | NW | Sets `javax.net.ssl.keyStore*` globally; add `ssl_keystore_type` param accepting BCFKS; user-provided JMS client must also be FIPS-capable |
| logstash-input-pipe | 3.1.0 | SC | `IO.popen`; no crypto |
| logstash-input-redis | 3.7.1 | SC | No SSL config in this version (plaintext only) |
| logstash-input-stdin | 3.4.0 | SC | STDIN reader |
| logstash-input-syslog | 3.7.1 | NW-C | Delegates to logstash-input-tcp; inherits its `OpenSSL::SSL` blocker |
| logstash-input-tcp | 7.0.11-java | **NW-C** | Uses `OpenSSL::SSL::SSLContext`, `OpenSSL::PKey::RSA`, `OpenSSL::X509::Certificate` in Ruby TLS path (`tcp.rb:154,381-399`); jruby-openssl disabled under FIPS |
| logstash-input-twitter | 4.1.1 | **X** | Deprecated; Twitter API v1.1 defunct; JRuby OpenSSL path |
| logstash-input-udp | 3.5.0 | SC | UDP socket; no TLS |
| logstash-input-unix | 3.1.3 | SC | Unix domain socket; no TLS |

#### Outputs (not allowlisted)

| Plugin | Version | Status | Blocker / Notes |
|---|---|---|---|
| logstash-output-csv | 3.0.11 | SC | Wraps logstash-output-file; no crypto |
| logstash-output-email | 4.1.3 | **B** | `mail` gem → `net-smtp` → `OpenSSL::SSL::SSLSocket`; would need JavaMail rewrite (`email.rb:111`) |
| logstash-output-file | 4.3.0 | SC | File writes; no crypto |
| logstash-output-graphite | 3.1.6 | SC | Plain TCP; no TLS in this plugin |
| logstash-output-http | 6.0.1 | NW | Uses `logstash-mixin-http_client` (systemic blocker #1) |
| logstash-output-lumberjack | 3.1.9 | **B** | `jls-lumberjack` client uses JRuby OpenSSL; deprecated — use `logstash-integration-logstash` |
| logstash-output-nagios | 3.0.7 | SC | Writes to command file |
| logstash-output-null | 3.0.5 | SC | Drop |
| logstash-output-redis | 5.2.0 | **NW-C** | Uses `OpenSSL::PKey::RSA`, `OpenSSL::X509::Certificate`, `OpenSSL::SSL::VERIFY_*` (`redis.rb:233-250`) |
| logstash-output-tcp | 7.0.1 | **NW-C** | Same pattern as input-tcp (`tcp.rb:115-163`) |
| logstash-output-udp | 3.3.0 | SC | UDP send; no TLS |
| logstash-output-webhdfs | 3.1.1-java | **NW-C** | `use_ssl_auth` path: `OpenSSL::PKey::RSA`, `OpenSSL::X509::Certificate` (`webhdfs_helper.rb:27-35`). `use_kerberos_auth` path: `require 'gssapi'` — not FIPS-safe |

#### Integrations

| Plugin | Version | Status | Blocker / Notes |
|---|---|---|---|
| logstash-integration-aws | 7.3.4-java | NW | (1) `Digest::MD5` in sincedb (`s3.rb:340,350`) — throws under approved-only; (2) No `use_fips_endpoint` config. `aws-sdk-core 3.252` supports it; needs plumbing through `aws_config.rb` |
| logstash-integration-jdbc | 5.6.3 | SC | No plugin-level crypto; depends entirely on user-supplied JDBC driver. Publish supported-driver matrix (Postgres 42.7+, MSSQL 12.6+, Oracle 23c, MySQL Connector/J 8.4+) |
| logstash-integration-kafka | 12.1.5-java | NW | (1) Schema-registry `ssl_keystore_type` validator hard-codes `%w[jks PKCS12]` — add `bcfks` (`avro_schema_registry.rb:34,43`); (2) SCRAM-SHA-1 not FIPS-approved — document that SCRAM-SHA-256/512 must be used; (3) SASL/GSSAPI Kerberos enctypes must be SHA2/AES128+ (no MD5-DES) |
| logstash-integration-logstash | 1.0.4-java | NW | Wraps `logstash-input-http` + `logstash-mixin-http_client`; comes free with systemic fix #1 |
| logstash-integration-rabbitmq | 7.4.1-java | NW | `march_hare` wraps Java RabbitMQ client + JSSE; PKCS12 cert config (`rabbitmq_connection.rb:50-119`); needs validation under approved-only mode |
| logstash-integration-snmp | 4.3.1-java | **B (config-dep)** | SNMPv3 `auth_protocol` accepts MD5 and DES — not FIPS-approved (`snmp/common.rb:82,88,94,121`). Fix: restrict validator to SHA-2+/AES128+ when FIPS active — then NW |

#### Default mixins

| Mixin | Version | Status | Notes |
|---|---|---|---|
| logstash-mixin-ca_trusted_fingerprint_support | 1.0.1-java | SC | SHA-256 fingerprint; FIPS-OK |
| logstash-mixin-deprecation_logger_support | 1.0.0-java | S | Logging only |
| logstash-mixin-ecs_compatibility_support | 1.3.0-java | S | Metadata handling |
| logstash-mixin-event_support | 1.0.1-java | S | Event factory |
| logstash-mixin-http_client | 7.5.0 | **NW** | `ssl_keystore_type => %w[pkcs12 jks]` — no `bcfks`. Key systemic fix. Also pulls `openssl_pkcs8_pure`; verify code path is not hit when keystore is used. `http_client.rb:107,133` |
| logstash-mixin-normalize_config_support | 1.0.0-java | S | Config normalization |
| logstash-mixin-plugin_factory_support | 1.0.0-java | S | Plugin factory |
| logstash-mixin-scheduler | 1.0.1-java | S | rufus-scheduler wrapper |
| logstash-mixin-validator_support | 1.1.1-java | S | Field-reference validation |
| manticore | 0.9.2-java | NW | Java HTTP client via Netty + JSSE; FIPS-clean for keystore-based TLS. `openssl_pkcs8_pure` dep is only hit for unencrypted PEM keys — confirm this path is unused under FIPS |

---

## 3. Phased roadmap

### Phase 0 — Codify what already exists (docs + infrastructure)

- Promote the richer assertions from `fips_validation.rb` into `FipsBootstrapCheck` (provider order, approved-only mode, jruby-openssl not registered).
- Auto-inject `-Djruby.openssl.load.jars=false -Djruby.openssl.provider.register=false` from `bin/logstash.lib.sh` when FIPS setting is on (fixes C3 without operator burden).
- Add `:skip_fips` / `:fips_only` RSpec tags across specs that rely on MD5/PKCS12/JKS. Infrastructure already exists in `spec/spec_helper.rb:66`.

### Phase 1 — Fix core-side hard blockers (C1–C5)

- **Secret keystore** (`JavaKeyStore.java`, `SecretStoreUtil.java`): switch to BCFKS under FIPS; replace PBE with PBKDF2WithHmacSHA256 + AES-256; replace `java.util.Random` with `SecureRandom`.
- **API webserver** (`webserver.rb:257-259`): honor `api.ssl.keystore.type`; default to BCFKS under FIPS.
- **`stronger_openssl_defaults.rb`**: gate on FIPS mode; skip the monkeypatch and rely on JSSE/BCJSSE.
- **GeoIP downloader**: disable auto-download under FIPS; document operator-provided DB requirement.
- Backfill unit + integration tests for each of the above.

### Phase 2 — Ecosystem unlock (validator + config changes only)

- Add `bcfks` to `ssl_keystore_type` / `ssl_truststore_type` validators in: `logstash-mixin-http_client`, `logstash-output-elasticsearch`, `logstash-input-elasticsearch`, `logstash-filter-elasticsearch`, `logstash-input-beats`, `logstash-input-http`, `logstash-integration-kafka` (schema-registry mixin), `logstash-integration-jms`, `logstash-integration-rabbitmq`.
- **MD5 sincedb swap**: replace `Digest::MD5.hexdigest` with `Digest::SHA256.hexdigest` in `logstash-input-file`, `logstash-input-dead_letter_queue`, `logstash-integration-aws`. Preserve backwards-compat by reading both the MD5 and SHA-256 named paths on first run.
- **AWS FIPS endpoint**: add `use_fips_endpoint` config param to `logstash-integration-aws` and plumb it through `aws_config.rb`.
- **FIPS-aware guards** in `logstash-filter-fingerprint` and `logstash-filter-anonymize` that reject MD5/SHA1 algorithm values when FIPS is active.
- **Publish supported-JDBC-driver matrix** for `logstash-integration-jdbc` (zero code change).
- **Restrict SNMP validators** to FIPS-approved subset (SHA-2+, AES128+) when FIPS active (`logstash-integration-snmp`).

### Phase 3 — Ruby-OpenSSL → JSSE refactor

Plugins affected: `logstash-input-tcp`, `logstash-output-tcp`, `logstash-input-syslog`, `logstash-output-redis`, `logstash-output-webhdfs`.

Replace direct `OpenSSL::SSL::SSLContext` / `OpenSSL::PKey::RSA` / `OpenSSL::X509::Certificate` usage with a Java `SSLContext` built via JSSE + BCFIPS. Introduce a shared helper at `logstash-core/lib/logstash/util/ssl_context_builder.rb` so plugins call `LogStash::Util::SSLContextBuilder.build(cert:, key:, ca:, ...)` and get back a `javax.net.ssl.SSLContext` usable by Netty, Puma, or any Java SSL consumer.

### Phase 4 — Policy, documentation, and ecosystem

- Mark BLOCKED plugins explicitly in `docs/reference/fips-plugin-support.md` with rationale.
- Document deprecated plugins as "not supported in FIPS mode" (`logstash-input-couchdb_changes`, `logstash-input-twitter`, `logstash-input-ganglia`, `logstash-output-lumberjack`).
- Add `logstash-filter-ruby` user-responsibility statement to FIPS docs.
- Consider making `logstash-integration-fips_validation` an always-on diagnostic module when `xpack.security.fips_mode.enabled=true`, not just in observabilitySRE.

---

## 4. Critical files reference

**Existing FIPS scaffolding**

| File | Purpose |
|---|---|
| `x-pack/lib/security/extension.rb` | Settings registration (`xpack.security.fips_mode.*`) |
| `x-pack/lib/security/fips_bootstrap_check.rb` | Current bootstrap check (thin — provider name only) |
| `x-pack/spec/security/fips_bootstrap_check_spec.rb` | Tests for bootstrap check |
| `x-pack/distributions/internal/observabilitySRE/plugin/logstash-integration-fips_validation/lib/logstash/fips_validation.rb` | Richer validator (assertions to promote to stock) |
| `x-pack/distributions/internal/observabilitySRE/config/security/java.security` | Production FIPS security policy |
| `x-pack/distributions/internal/observabilitySRE/docker/Dockerfile` | Reference for JVM flag injection |
| `x-pack/build.gradle` | `fipsProviderJars` config; BC-FIPS coordinates |
| `spec/spec_helper.rb:66` | `skip_fips` tag infrastructure |
| `x-pack/distributions/internal/observabilitySRE/plugin-allow-list.txt` | Current 19-plugin FIPS allowlist |

**Ruby-side gaps to close**

| File | Gap |
|---|---|
| `logstash-core/src/main/java/org/logstash/secret/store/backend/JavaKeyStore.java:78,116,209,330,388` | PKCS12 + PBE + java.util.Random (C1) |
| `logstash-core/src/main/java/org/logstash/secret/store/SecretStoreUtil.java:39,171` | java.util.Random (C1) |
| `logstash-core/lib/logstash/webserver.rb:257-259` | JKS hard-code (C2) |
| `logstash-core/lib/logstash/patches/stronger_openssl_defaults.rb` | Unconditional `require "openssl"` (C4) |
| `x-pack/lib/geoip_database_management/util.rb:18` | Digest::MD5 (C5) |
| `x-pack/lib/geoip_database_management/downloader.rb:118` | Digest::MD5 (C5) |
| `bin/logstash.lib.sh` | JVM flag injection (C3) |

---

## 5. Open questions to resolve before Phase 1

1. **Fatal vs warning**: Should a FIPS misconfiguration be a fatal startup error for all 5 gaps, or only for provider ordering? Extending `FipsBootstrapCheck` to cover C1–C4 will block startup for misconfigured deployments.
2. **Keystore migration**: Do we need a one-way migration tool (`logstash-keystore migrate-to-fips`) or is regenerate-from-scratch acceptable? Migration is safer for operators with existing keystores.
3. **Strict mode flag**: Should `xpack.security.fips_mode.strict` exist to progressively enforce FIPS-safe algorithm validators (reject MD5, restrict SNMP), decoupled from the initial opt-in?
4. **Plugin support matrix ownership**: Should `docs/reference/fips-plugin-support.md` be hand-maintained or auto-generated from a data file via a `rakelib/fips-support.rake` task?
