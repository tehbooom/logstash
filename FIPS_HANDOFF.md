# Logstash FIPS 140-3 — Engineering Handoff / State Document

**Purpose:** Enable someone with no prior context (only the code) to continue this
work. Read this top to bottom before touching any plugin.

**Scope of the effort:** Make Logstash and a targeted set of `logstash-plugins`
plugins FIPS 140-3 *compliant at the algorithm-selection level* when an operator
opts into FIPS mode. This is compliance-by-construction on top of a validated
module (BouncyCastle FIPS), **not** FIPS *validation* of Logstash itself.

> **Before you trust anything below:** run `git status` in the core checkout and in
> each plugin repo. Several agents reported results during development; this doc
> reflects intended state, but disk is the source of truth. At least one stale/
> wrong-agent report and one untracked-file scare occurred during development.
> Also: the plugin guards depend on a logstash-core that ships `LogStash::FIPS`.
> Plugin changes must not be *released* ahead of a core release containing the
> module, or users installing the updated plugin against older core hit
> `NoMethodError`. Note the minimum-core-version dependency in each plugin PR.

---

## 1. Architecture & Key Decisions (with rationale)

### 1.1 C:HYBRID mode → guards are the SOLE enforcement

Logstash runs BouncyCastle FIPS (BCFIPS) in **C:HYBRID mode** (matching
Elasticsearch), i.e. **without** `-Dorg.bouncycastle.fips.approved_only=true`.

**Empirically confirmed** by `x-pack/qa/fips-hybrid-check.rb`: with BCFIPS 2.0.1
inserted as provider #1, `javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")`
**succeeds** — the provider does *not* refuse non-approved algorithms at the JCE
level in hybrid mode. Enforcement (approved-only) only happens if that JVM flag is
set, which Logstash deliberately does not set.

**Consequence:** the plugin/core-level algorithm checks are the **entire**
enforcement mechanism, not defence-in-depth. There is no provider backstop. Do not
weaken or remove a guard on the assumption "BCFIPS will catch it" — it will not.
This is why coverage matters: a crypto call path not routed through `check!` is
simply unenforced.

Keep `x-pack/qa/fips-hybrid-check.rb` in-tree as a regression check. If a future
BCFIPS/JVM upgrade ever *does* enforce at the JCE level, that script is what tells
you the guards became defence-in-depth again.

### 1.2 `LogStash::FIPS.check!(algorithm:, use:)` design

Location: `logstash-core/lib/logstash/fips.rb`. Spec:
`logstash-core/spec/logstash/fips_spec.rb`.

- `enabled?` reads an **explicit** operator setting `fips_mode.enabled` (registered
  in `logstash-core/lib/logstash/environment.rb`, default `false`). It degrades
  safely: returns `false` (no-op) if the setting isn't registered, so early calls
  don't raise.
- **Why an explicit setting, not provider inference:** in C:HYBRID the BCFIPS
  provider is *always* loaded but `approved_only` is off, so provider presence does
  **not** encode operator intent to enforce policy. Only an explicit setting does.
- `check!(algorithm:, use:)` is a **no-op when disabled** (non-FIPS deployments are
  completely unaffected). When enabled and the algorithm is not approved for the
  given `use`, it raises `LogStash::ConfigurationError` naming the algorithm, the
  use, and approved alternatives.
- `use:` categories: `:digest_security`, `:hmac`, `:cipher`, `:signature`, `:kdf`,
  `:rng`.

### 1.3 Probe-derived floor (`BCFIPS_REGISTERED`) vs use-layer `POLICY`

- `BCFIPS_REGISTERED` = what BCFIPS 2.0.1 will *compute/operate* under approved-only
  mode, derived by `x-pack/qa/fips-approved-probe.rb` using **operation-level**
  verification (perform a representative op with conformant params; catch the Java
  `Error`/`FipsUnapprovedOperationError`, NOT a bare Ruby `rescue`). Named
  `_REGISTERED` (not `_APPROVED`) deliberately — it is "what the provider computes,"
  not "what policy approves."
- `POLICY[use]` = the **narrower**, use-aware approved set applied on top.

**The primitive-vs-approval gap (why the two layers exist):** the provider
approving a *primitive* is not the same as it being approved for a *use*:
  - **MD5** is registered/operable (BCFIPS uses it internally, e.g. TLS PRF) — so a
    naive probe reported it "approved." It must be **rejected** for
    `:digest_security`, `:signature`, `:hmac`. (An early probe bug used
    `getInstance` which measured *registration*, not *approval*, and falsely passed
    MD5; the probe was rewritten to operation-level. Verify MD5 still rejects.)
  - **DSA** (`SHA256withDSA`, `SHA1withDSA`) is registered by BCFIPS 2.0.1 but
    **excluded** from `POLICY[:signature]` per **FIPS 186-5 (Feb 2023)** which
    withdrew DSA for new signature generation.
  - **3DES / DESede** is registered (140-2 legacy) but **excluded** from
    `POLICY[:cipher]` because we target 140-3 only.
  - **SHA-1**: approved as raw digest and for HMAC by BCFIPS, but **excluded** from
    `:digest_security` and `:signature`; **included** in `:hmac` (see 1.4).

`fips_spec.rb` includes a **round-trip invariant**: every value in every `POLICY`
set must normalize back to itself, so adding an algorithm to `POLICY` without a
matching alias fails a test rather than silently becoming unreachable. Reverse
aliases for POLICY members are auto-generated at load; `ALIASES` only needs to
cover *alternate* spellings.

### 1.4 The HMAC-SHA-1 asymmetry (the single most review-worthy rule)

**HMAC-SHA-1 is FIPS-approved; bare/HMAC-MD5 is not.** HMAC's security does not
depend on SHA-1 collision resistance (SP 800-131A rev2 approves HMAC-SHA1).

Concretely, for `use: :hmac`:
- `"sha1"` / `"SHA1"` → normalizes to `"SHA-1"` → **PASSES**.
- `"md5"` / `"MD5"` → `"MD5"` → **REJECTS**.

For `use: :digest_security` and `use: :signature`, SHA-1 **rejects**. Same
primitive, different verdict by use — this is the whole point of the `use:`
parameter. When reviewing any HMAC-guarded plugin, verify the pair:
**SHA1 passes, MD5 rejects.** If SHA1 raises, someone treated it like a signature;
if MD5 passes, the guard didn't attach.

### 1.5 Parameter boundary — algorithm SELECTION only

`check!` receives an algorithm *name* and a *use*. It never sees keys, key sizes,
iteration counts, salts, IVs, or curves. Therefore it does **not** validate any
cryptographic parameter. Examples that PASS the gate despite being non-conformant
on parameters: RSA-1024 with `SHA256withRSA`; PBKDF2 with 1 iteration; a reused
GCM IV.

**Why scoped this way:** a name-based gate is one centralized, testable thing.
Parameter validation is per-operation, scattered, requires intercepting real key
material at each call site — out of scope for the current gate.

**Operator-supplied key files (RSA/EC in TLS/keystore plugins):** an operator
loading a sub-2048-bit RSA key into a FIPS deployment is **not** stopped. This is a
**deliberate scope decision**, documented, not an oversight — the size lives in the
operator's file, and validating it would require inspecting loaded key objects at
every TLS/keystore site. If key-parameter enforcement is later required, it must be
added as a **post-load** check at each key-loading site (reading the real key
object), gated behind the same `enabled?` no-op.

The gate's guarantee is precisely: *no banned algorithm was selected through a
checked call site.* It is **not** "the crypto is FIPS-conformant."

---

## 2. What's Done (per plugin)

> Branch: all work on a local `fips` branch per repo. **Commits: local only, never
> pushed** (deliberate — see §5). Verify actual commit state with `git status`/`git
> log` per repo; treat any "committed?" claim below as *to be verified*.

### 2.1 Core — `LogStash::FIPS`
- **Files:** `logstash-core/lib/logstash/fips.rb`, spec
  `logstash-core/spec/logstash/fips_spec.rb`, setting registered in
  `logstash-core/lib/logstash/environment.rb` (`fips_mode.enabled`, default false).
- **Probe:** `x-pack/qa/fips-approved-probe.rb` (operation-level, BCFIPS 2.0.1),
  and `x-pack/qa/fips-hybrid-check.rb` (the sole-enforcement proof).
- **Contents:** `BCFIPS_REGISTERED` floor, use-aware `POLICY`, `ALIASES`
  (incl. OpenSSL-style cipher names added for the cipher plugin — see 2.2),
  `check!`, `enabled?`, `normalize` (downcase→ALIASES; `normalize` is private to
  includers), round-trip invariant spec.
- **`require`:** `LogStash::FIPS` is **NOT autoloaded** by `require "logstash-core"`.
  Guarded plugins must `require "logstash/fips"` explicitly. (Confirmed via probe
  from inside a plugin's bundle.)
- **Plugin→core resolution (dev):** plugins resolve local core from source via
  `LOGSTASH_SOURCE=1` + `LOGSTASH_PATH=<abs path to ../../logstash>`; requires
  JRuby (e.g. `rbenv jruby-10.x`). `:path` gem reads the working tree, so commit
  `fips.rb` on the core branch — an untracked file will be invisible to a git-ref
  based resolution.
- **Spec toggle mechanism (use this in plugin specs):** stub the predicate —
  `allow(LogStash::FIPS).to receive(:enabled?).and_return(true|false)`. Preferred
  over driving `LogStash::SETTINGS` because it tests the guard in isolation from
  core's settings machinery. (Settings-based toggle exists but couples plugin specs
  to `logstash/environment` load; reserve it for core's own spec.)

### 2.2 `logstash-filter-cipher` — DONE
- **Changed:** `require "logstash/fips"`; single
  `LogStash::FIPS.check!(algorithm: @algorithm, use: :cipher)` in `register`;
  comment at the `config :algorithm` validator documenting the GCM/AEAD limitation.
- **Core ALIASES added:** OpenSSL-style cipher names, because the plugin passes
  names like `"aes-256-cbc"`, not JCE `"AES/CBC/PKCS5Padding"`. Approved →
  `aes-{128,192,256}-{cbc,gcm,ctr}` map to canonical POLICY members. Non-approved →
  `aes-*-ecb` → `AES/ECB/NoPadding` (**not** in POLICY, rejects), plus `aes-*-ofb`,
  `aes-*-cfb`, `des-cbc`, `des-ede3-cbc`, etc. **⚠ The `aes-*-ofb`/`aes-*-cfb`
  mappings assume OFB/CFB are non-approved — this assumption is UNRESOLVED, see
  §3.1. If OFB is approved, these aliases and POLICY must change.**
- **Finding — GCM unreachable:** JRuby's `OpenSSL::Cipher.ciphers` does **not**
  include GCM/AEAD entries even with BCFIPS 2.0.1 active. The plugin's `:algorithm`
  validator (`:validate => OpenSSL::Cipher.ciphers`, evaluated at class-load) thus
  rejects GCM before `register`. So AES-GCM is **structurally unavailable** through
  this plugin on JRuby. This is a JRuby-OpenSSL-*surface* limitation (the plugin's
  cipher list), not necessarily a JVM/BCFIPS limitation. Documented in a validator
  comment + CHANGELOG. **No GCM IV-length check** was written — it would guard an
  unreachable path (dead code). ECB, though present in the list, is rejected under
  FIPS by `check!`.
- **Specs:** through the real `config_init` path (no instance bypass), stubbing
  `enabled?`. Confirmed: `aes-256-cbc` passes (FIPS on); `aes-256-ecb` raises;
  `des-ede3-cbc` raises; all pass when FIPS off.
- **CHANGELOG:** entry added (states the guard + GCM finding).

### 2.3 `logstash-filter-fingerprint` — DONE (split treatment)
- **Two crypto uses, different treatment:**
  - **Keyed HMAC** (when `key` configured): SECURITY → guarded with
    `check!(algorithm: @method.to_s, use: :hmac)` in the OpenSSL/else branch (the
    primary keyed path for SHA1/SHA256/SHA384/SHA512/MD5), and in the `:MURMUR3` /
    `:MURMUR3_128` branches gated `if @key`. **Verify** whether MURMUR3 can actually
    take a key — if not, those two guard lines are dead (harmless) and should carry
    a note.
  - **Keyless digest** (no key — dedup/document-id): NON-SECURITY → inline comment
    only, **not** routed through `check!`.
- **Step-0 normalization:** SHA1→SHA-1 (approved), SHA256/384/512 approved,
  MD5→rejects, MURMUR3→`"murmur3"`→rejects. No core ALIASES gap.
- **Split proof (the key assertions):** FIPS on + key + MD5 → **raises**; FIPS on +
  **no key** + MD5 → **no raise**. Both required. If both raise, guard leaked onto
  the dedup path; if neither, guard missed the HMAC path.
- **Specs:** real config path, `enabled?` stubbed. SHA1 passes, MD5 raises, MURMUR3
  (keyed) raises, keyless MD5 no-raise, FIPS-off no-op. CHANGELOG entry added.

### 2.4 `logstash-filter-anonymize` — DONE
- **Changed:** `require "logstash/fips"`; `check!(..., use: :hmac)` on the keyed-HMAC
  path. MD5 **rejects** under FIPS, SHA1 **passes** (HMAC-SHA1).
- **Do NOT** remove MD5/SHA1 from the plugin's algorithm validator — that's a
  separate breaking change on a non-FIPS track (§5). The FIPS guard rejecting MD5
  under FIPS mode is the correct scoped action; the validator stays as-is.
- **Non-security verdict (earned, not assumed):** `MURMUR3` — key is required by
  schema but **ignored in code** (`anonymize_murmur3` never reads `@key`); no secret,
  MurmurHash trivially invertible → genuinely non-security dedup/bucketing (the
  plugin *name* is misleading). `IPV4_NETWORK` — key is a subnet prefix length,
  deterministic/reversible → non-security. Both commented, unguarded.
- **Pre-existing bug (NOT ours):** `anonymize_murmur3` references `Fixnum` (removed
  in JRuby 10) → `NameError`. Exists on `main`. Logged as a FIXME at the site +
  CHANGELOG "Known bug" entry (fix: `when Fixnum` → `when Integer`). Do **not** fold
  this fix into a FIPS commit. Note: this path is currently broken on the runtime
  Logstash uses, which somewhat moots its FIPS treatment until fixed.
- **Specs:** 13/14 (the 1 failure is the pre-existing Fixnum bug, not FIPS).

### 2.5 `logstash-filter-hashid` — DONE
- **Changed:** `require "logstash/fips"`; `check!(algorithm: @method, use: :hmac)`
  as the **first line of `register`** (always keyed HMAC, no keyless path → guard
  unconditionally).
- **Step-0:** SHA1/256/384/512 approved, MD5 rejects. No ALIASES gap.
- **Specs:** 20/20. MD5 raises under FIPS, SHA1 does not. FIPS-off no-op.

---

## 3. Open / In-Flight

### 3.1 AES-OFB policy decision — UNRESOLVED, decide FIRST
**Question:** is AES-OFB (and AES-CFB) FIPS-approved in BCFIPS 2.0.1, i.e. should it
enter `POLICY[:cipher]`? OFB/CFB are NIST-defined modes (SP 800-38A), so exclusion
may be an **untested omission** rather than a disapproval — the original probe
candidate list included only CBC/GCM/CTR (+ non-AES), NOT OFB/CFB.

**Resolve via the probe** (operation-level, approved-only, conformant params — not
`getInstance`). Do NOT decide from the spec or intuition; the probe is the
authority (same discipline that caught the MD5 false-approval).

**What the verdict changes:**
- **If APPROVED:** add `AES/OFB/NoPadding` (and `AES/CFB/NoPadding` if it passed) to
  `POLICY[:cipher]`; add/repoint OpenSSL aliases (`aes-*-ofb`/`aes-*-cfb`, currently
  mapped to reject — see 2.2 ⚠); extend the probe candidate list so OFB/CFB are
  permanently in the probe-of-record; add round-trip spec coverage. **collectd's
  Encrypt path then works under FIPS** instead of hard-failing.
- **If REJECTED:** OFB stays out; the existing cipher aliases are correct; document
  **collectd's Encrypt security level as unavailable under FIPS** (CHANGELOG +
  comment), same treatment as the cipher-GCM finding.

This decision **gates collectd's specs** — settle it before writing them.

### 3.2 `logstash-codec-collectd` — analyzed, not yet implemented
Guards to add (pending §3.1 for the Encrypt path):
- **Sign path:** `OpenSSL::HMAC.digest("sha256", key, payload)` → HMAC-SHA256,
  keyed security → `check!(algorithm: "sha256", use: :hmac)`. ✅ approved.
- **Encrypt key derivation:** `@sha256.digest(key)` — raw SHA-256 digest used to
  derive key material → `check!(algorithm: "sha256", use: :digest_security)`
  (approved). Add a comment noting it's a **raw-digest** key derivation
  (protocol-defined), not PBKDF2, hence `:digest_security` not `:kdf`.
- **Decrypt checksum:** `@sha1.digest(plaintext)` — SHA-1 integrity checksum on the
  collectd **wire format** (protocol-mandated, not user-chosen) → **out-of-boundary
  inline comment**, no guard. Same class as S3 Content-MD5.
- **Encrypt cipher:** `OpenSSL::Cipher.new('AES-256-OFB')` — **pending §3.1.** If OFB
  approved → passes; if not → `check!(..., use: :cipher)` raises and Encrypt mode is
  documented unavailable.

### 3.3 SNMP pair — `logstash-input-snmp` + `logstash-integration-snmp`
Two independent axes. **Normalization must be LOCAL to the plugin, NOT in core
ALIASES** — these are SNMP4J/RFC-3414 protocol keywords (e.g. `hmac192sha256`,
`sha2`) meaningful only to SNMP; putting them in core pollutes the shared table and
`sha2` is ambiguous outside SNMP. Map locally to canonical names, then `check!` the
mapped value.

- **`auth_protocol` → `use: :hmac`** (local map → canonical, then check!):
  `md5`→`MD5` (**rejects**); `sha`→`SHA-1` (**passes**, HMAC-SHA1); `sha2`→`SHA-256`;
  `hmac128sha224`→`SHA-224`; `hmac192sha256`→`SHA-256`; `hmac256sha384`→`SHA-384`;
  `hmac384sha512`→`SHA-512` (all pass). **Review the `sha` passes / `md5` rejects
  pair.**
- **`priv_protocol` → `use: :cipher`**: `aes`/`aes128/192/256` → approved AES form
  (passes); `des`, `3des` → reject.
- The SNMPv3 **KDF** is internal to SNMP4J (RFC 3414) — out of our reach, not
  guarded. Guard the protocol *selection*, not the KDF.
- Apply identically to standalone gem and the integration gem if they share code.

---

## 4. Remaining Guard Set & The Standard Pattern

**Remaining:** collectd (§3.2), SNMP pair (§3.3). (cipher, fingerprint, anonymize,
hashid done.)

**Standard pattern for a guarded plugin:**
1. `require "logstash/fips"` at the top of the file calling `check!` (NOT autoloaded).
2. **Step 0 — normalization check (read-only, before coding):** determine the exact
   strings the plugin passes to `check!` in the plugin's own spelling; verify each
   normalizes correctly (approved→passes, weak→rejects). If a value doesn't
   normalize, fix it in **core ALIASES with a round-trip spec** (for general algo
   names) or a **local map** (for domain/protocol keywords like SNMP's) — never a
   per-plugin workaround for a general name.
3. Single `LogStash::FIPS.check!(algorithm: <value>, use: <category>)` in `register`
   with the **explicit** `use:`. Never let the agent infer `use:` — inference
   silently swaps `:hmac`↔`:digest_security`.
4. **Split treatment** where applicable: guard the security path (keyed HMAC,
   cipher), comment the non-security path (dedup/doc-id/protocol checksum) as
   out-of-boundary — do not guard it.
5. **Specs:** through the real `config_init` path (no instance bypass); stub
   `LogStash::FIPS.enabled?` for on/off. Must include the keyed/keyless proof where
   relevant and the SHA1-passes/MD5-rejects pair for HMAC.
6. **CHANGELOG** entry. **Local commit only, no push.**

**`use:` quick reference:** keyed HMAC → `:hmac`; symmetric encryption → `:cipher`;
security digest / raw-digest key derivation → `:digest_security`; digital signature
→ `:signature`; PBKDF2/scrypt → `:kdf`; SecureRandom DRBG → `:rng`. UUID generation
and non-security/protocol checksums are **out of scope** — comment, don't guard.

---

## 5. Cross-Cutting Rules (established during this work)

- **Separate commit tracks.** TLS peer-verification hardening
  (`VERIFY_NONE`→`VERIFY_PEER`) and `OpenSSL::PKey::RSA.new`→`PKey.read` correctness
  fixes are **NOT** FIPS algorithm-policy changes. Keep them on their own clearly
  labeled commits/branches. Mixing them into FIPS commits muddies the compliance
  boundary for auditors. (VERIFY_PEER is best practice / FedRAMP-adjacent, **not** a
  FIPS requirement, and is a breaking default change requiring an `ssl_verify`
  opt-out — handle deliberately, elsewhere.)
- **`bcfks` keystore-type enum additions** are additive/non-breaking and FIPS-relevant
  — safe, but still their own change.
- **Local commits only; never push** (CI resource discipline — operator manages
  pushes).
- **Document, don't just reject.** When a guard makes a plugin capability
  unreachable under FIPS (cipher GCM; potentially collectd Encrypt/OFB), that's a
  user-facing **capability limitation** — record it in CHANGELOG + code comment so a
  user hitting the hard failure understands it's intentional, not a bug.
- **Unknown → reject (fail closed).** For a sole-enforcement gate, an unaliased/
  unknown algorithm normalizing to a non-POLICY form and rejecting under FIPS is the
  correct direction. Better to reject an approved-but-unaliased algorithm (someone
  files a bug, you add the alias) than silently pass a non-approved one.
- **The probe decides, not priors.** Every "is X approved" question is settled by
  operation-level probing against the pinned BCFIPS jar, not by the NIST spec, docs,
  or memory. Re-run the probe on any BCFIPS upgrade; the approved list is jar-pinned.

---

## 6. Compliance-Scope Statement (for assessors)

> **FIPS 140-3 compliance scope — Logstash algorithm-policy gate.**
>
> This implementation enforces **FIPS-approved algorithm *selection*** for
> designated cryptographic operations when the operator sets `fips_mode.enabled:
> true`. It does **not** perform, and does not claim, FIPS *validation* of Logstash.
> The validated cryptographic module is BouncyCastle FIPS (BCFIPS); Logstash is
> **compliant-by-construction** on top of it.
>
> - **Sole enforcement (C:HYBRID).** BCFIPS runs in hybrid mode (approved-only
>   disabled), so the provider does not refuse non-approved algorithms at the JCE
>   level. The `LogStash::FIPS` gate is the *only* enforcement of algorithm policy;
>   there is no provider backstop. Coverage of crypto call sites is therefore
>   load-bearing.
> - **Algorithm-selection only.** The gate validates algorithm *names* per use
>   category. It does **not** validate any cryptographic *parameter* — key size,
>   curve, PBKDF2 iteration count, salt length, or IV construction/uniqueness. E.g.
>   a sub-2048-bit RSA key or a 1-iteration PBKDF2 passes. Parameter conformance,
>   where required, must be enforced at the operation site.
> - **Operator-supplied key material.** Bit-length/curve of operator-supplied RSA/EC
>   keys and certificates (TLS/keystore inputs) is **not** validated; supplying
>   conformant key material is the operator's responsibility. Deliberate scope
>   boundary.
> - **Jar-pinned approved set.** The approved-algorithm list is derived by
>   operation-level probing of a specific BCFIPS version (2.0.1) and must be
>   re-derived on any module upgrade. See `x-pack/qa/fips-approved-probe.rb`.
> - **Deliberate boundary exceptions** (reviewed, documented in code):
>   - **HMAC-SHA-1** is permitted for `:hmac` (approved per SP 800-131A rev2; HMAC
>     security does not rely on SHA-1 collision resistance) while SHA-1 is rejected
>     for `:digest_security` and `:signature`.
>   - **Non-security / protocol-mandated digests** (e.g. S3 Content-MD5, collectd
>     wire-format SHA-1 checksum, dedup/document-id hashing) are out of the
>     cryptographic boundary and intentionally not gated.
>   - **DSA** signatures excluded (FIPS 186-5 withdrawal); **3DES** excluded (140-3
>     target); **AES-GCM** unavailable in `logstash-filter-cipher` on JRuby due to
>     the plugin's `OpenSSL::Cipher.ciphers`-derived validator.
>
> The gate's guarantee is precisely: *no non-approved algorithm was selected through
> a checked call site.* It is not a guarantee that all cryptographic operations are
> FIPS-conformant. Independent assessment against the target FIPS profile is
> required before any formal compliance claim.

---

## Immediate next action
1. **Resolve §3.1 (AES-OFB probe).** It gates collectd and may change
   `POLICY[:cipher]` + existing cipher aliases.
2. Implement **collectd** (§3.2) against the settled cipher policy.
3. Implement **SNMP pair** (§3.3) with local keyword normalization.
4. Run `git status` across all repos; verify on-disk state matches this doc.
5. Land the compliance-scope statement (§6) in the repo docs.
