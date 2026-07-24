# Deploying Logstash in FIPS Mode

## 1. Load-order ownership

Logstash is responsible for loading the FIPS gem. It loads the gem through
`fips_jruby_openssl.rb` before any pipeline code runs.

The user or deployment is responsible for registering the security providers in
`java.security` before the JVM starts. Logstash does not self-register providers.

## 2. Provider configuration (`java.security`)

The four provider entries below are the minimum wiring. They are not a complete
`java.security` policy on their own. Base deployment configuration on the full
fixture at `x-pack/qa/integration/fips-validation/fixtures/java.security`, which
registers BCFIPS in hybrid mode (`C:HYBRID;ENABLE{All};`), not approved-only
mode. The fixture also sets keystore defaults, disabled-algorithm lists, and
other JDK security properties required for a working FIPS deployment.

Register the providers in this order:

```properties
security.provider.1=org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider C:HYBRID;ENABLE{All};
security.provider.2=org.bouncycastle.jsse.provider.BouncyCastleJsseProvider fips:BCFIPS
security.provider.3=SUN
security.provider.4=-BC
```

Do not register SunJSSE; omit it entirely.

Copy the provided example to enable the FIPS provider wiring:

```shell
cp config/jvm.options.d/fips.options.example config/jvm.options.d/fips.options
```

The `.options` suffix enables the file; Logstash ignores the `.example` file.
The enabled file supplies:

```text
-Djruby.openssl.provider.register=false
-Djruby.openssl.fips.provider=BCFIPS:2*
-Djruby.openssl.fips.ssl.provider=BCJSSE:2*
```

Add `java.security.properties==<path>` (double equals) to `fips.options` to
replace the entire security policy instead of appending to the JDK's policy:

```text
-Djava.security.properties==/etc/logstash/java.security
```

Point that path at a copy of the full fixture (or a deployment-specific file
derived from it), not a providers-only excerpt.

## 3. Truststore provisioning

BCFIPS cannot load JKS keystores. Use BCFKS format. Create a BCFKS truststore
from the JDK's default `cacerts`:

```shell
keytool -importkeystore \
  -srckeystore $JAVA_HOME/lib/security/cacerts \
  -srcstoretype JKS \
  -srcstorepass changeit \
  -destkeystore /etc/logstash/cacerts.bcfks \
  -deststoretype BCFKS \
  -deststorepass <password> \
  -noprompt \
  -provider org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider \
  -providerpath /path/to/bc-fips.jar:/path/to/bcpkix-fips.jar:/path/to/bcutil-fips.jar:/path/to/bctls-fips.jar
```

All four BCFIPS jars (`bc-fips`, `bcpkix-fips`, `bcutil-fips`, and
`bctls-fips`) must appear on `-providerpath`.

Add the truststore configuration to `config/jvm.options.d/fips.options`:

```text
-Djavax.net.ssl.trustStore=/etc/logstash/cacerts.bcfks
-Djavax.net.ssl.trustStoreType=BCFKS
-Djavax.net.ssl.trustStoreProvider=BCFIPS
-Djavax.net.ssl.trustStorePassword=<password>
```

## 4. Kafka SSL requirement

When using `logstash-integration-kafka` under FIPS,
`ssl_keystore_type` and `ssl_truststore_type` must be set explicitly to `PKCS12`
or `bcfks`. If either setting is omitted, Kafka defaults to JKS, which BCFIPS
cannot load.

Schema Registry settings, including `schema_registry_ssl_keystore_type` and
`schema_registry_ssl_truststore_type`, have the same requirement.

SASL/Kerberos is not supported under FIPS. The JVM has no FIPS 140-validated
GSSAPI implementation, and the reference `java.security` fixture does not
register `SunJGSS`/`SunSASL`. Use mTLS instead of SASL/Kerberos for Kafka
authentication in FIPS deployments.

## 5. JMS SSL — plugin-managed SSL unsupported

`logstash-input-jms` rejects its SSL keystore/truststore settings when BCFIPS is
the first security provider because those options set JVM-wide
`javax.net.ssl.*` system properties that conflict with deployment-owned BCFKS
configuration.

`logstash-output-jms` does not implement those SSL system-property settings and
has no FIPS guard. Do not rely on plugin-managed SSL options in either plugin
under FIPS.

Deployment-level JSSE settings (for example, the four
`javax.net.ssl.trustStore*` properties in `fips.options`) still apply to
`ssl://` broker connections. Configure TLS through those deployment settings or
a provider-specific JMS connection factory instead.

## 6. Hybrid algorithm policy (MD5, SHA-1)

The reference `java.security` fixture runs BCFIPS in hybrid mode
(`C:HYBRID;ENABLE{All};`). Hybrid mode permits non-security uses of MD5 and
other legacy algorithms through the JVM's available providers (SUN is registered
at provider position 3), while security-sensitive operations such as TLS and
key derivation remain subject to FIPS validation. For example, GeoIP database
integrity checks use MD5 digests via default provider selection and continue to
work under the hybrid fixture.

Approved-only mode (`org.bouncycastle.fips.approved_only=true`) rejects those
non-security MD5 uses. Logstash does not implement a separate
`LogStash::FIPS.check!` gate; rejection is handled by the configured providers.
Plugins that configure MD5 or SHA-1 for security purposes log a register-time
warning when BCFIPS is the first provider.

Review pipeline configurations and replace prohibited algorithms before moving
to approved-only mode.

## 7. Packaging model

Two gems are published:

- `jruby-openssl` is the normal artifact and bundles non-FIPS Bouncy Castle.
- `jruby-openssl-fips` is the FIPS artifact and bundles no Bouncy Castle
  libraries. The deployment must provide `bc-fips`, `bcpkix-fips`,
  `bcutil-fips`, and `bctls-fips` on the JVM classpath.

The tested FIPS module versions are:

- `bc-fips`: 2.0.1
- `bcpkix-fips`: 2.0.7
- `bcutil-fips`: 2.0.5
- `bctls-fips`: 2.0.22

The Logstash FIPS distribution depends on `jruby-openssl-fips`. It includes a
compatibility shim so existing `require "jruby-openssl"` calls in plugins resolve
to the FIPS implementation.
