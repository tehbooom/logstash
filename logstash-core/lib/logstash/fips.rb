# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# LogStash::FIPS — algorithm-policy gate for FIPS 140-3 deployments.
#
# SOLE-ENFORCEMENT RATIONALE:
#   Logstash runs BouncyCastle FIPS in C:HYBRID mode (matching Elasticsearch).
#   In C:HYBRID mode BCFIPS does NOT set approved_only, so non-approved
#   algorithms are accepted at the JCE level without error.  Empirically
#   confirmed by x-pack/qa/fips-hybrid-check.rb:
#     "BCFIPS explicit:  ACCEPTED DES/CBC => approved_only NOT enforced at JCE level"
#   Therefore check! is the SOLE enforcement of FIPS algorithm policy in this
#   process.  Do NOT weaken or bypass this gate assuming the provider will catch
#   violations — it will not in C:HYBRID mode.
#
# APPROVED-ALGORITHM DERIVATION:
#   BCFIPS_REGISTERED was produced by x-pack/qa/fips-approved-probe.rb against
#   BCFIPS 2.0.1 (bctls-fips 2.0.22, bcutil-fips 2.0.5) under the JVM flag
#   -Dorg.bouncycastle.fips.approved_only=true.  Under that flag BCFIPS prunes
#   its JCE service table so that absent algorithms were never registered; a
#   successful getInstance is a reliable "registered under approved-only" signal.
#   KDF entries (PBKDF2, scrypt) were additionally confirmed at operation level
#   with conformant parameters (password >= 112 bits).
#   Re-run the probe script when BCFIPS jars are upgraded.
#
#   Key findings (BCFIPS 2.0.1):
#     - MD5 MessageDigest: absent under approved-only.
#     - SHA-1 MessageDigest: registered; excluded from :digest_security and
#       :signature by policy.
#     - DSA signatures: registered by BCFIPS 2.0.1; excluded from :signature
#       because FIPS 186-5 (Feb 2023) withdrew DSA for new signature generation.
#     - DESede (3DES): registered for FIPS 140-2 legacy compat; excluded from
#       :cipher since we target 140-3.
#     - AES/OFB/NoPadding and AES/CFB/NoPadding: confirmed approved at
#       operation level under BCFIPS 2.0.1 approved_only=true.  AES/CFB
#       resolves to CFB128 (full-block feedback — JCE default when no width
#       suffix is given), which is the mode required by SNMPv3 AES privacy
#       (RFC 3826).
#     - PBKDF2 variants and scrypt: registered and confirmed approved at
#       operation level with conformant parameters.
#     - SecureRandom: BCFIPS 2.0.1 exposes "DEFAULT" and "NONCEANDIV" as JCE
#       names; internal DRBG type names (CTR_DRBG etc.) are not JCE aliases.
#
# USE-RESTRICTION LAYER:
#   BCFIPS_REGISTERED is the provider floor — "what the provider computes under
#   approved-only mode."  POLICY narrows it for use-contextual restrictions:
#     - SHA-1 allowed for :hmac (HMAC-SHA-1 is approved per SP 800-131A rev2;
#       HMAC's security does not depend on SHA-1 collision resistance — this is
#       an explicit policy decision, not an inherited default).
#     - SHA-1 excluded from :digest_security and :signature.
#     - DSA excluded from :signature per FIPS 186-5 withdrawal.
#     - DESede excluded from :cipher (140-3 target).
#
# COMPLIANCE SCOPE (for assessors):
#   This gate enforces algorithm *selection* only.  It does not and cannot verify:
#     - Key sizes, iteration counts, salt lengths, or IV reuse.  A caller passing
#       PBKDF2WithHmacSHA256 with 1 iteration passes check!; conformant parameters
#       are the caller's responsibility.
#     - RSA key length (>= 2048) or EC curve selection — those are parameter-level
#       constraints outside algorithm naming.
#   The approved set is pinned to BCFIPS 2.0.1 (bcutil-fips 2.0.5, bctls-fips 2.0.22).
#   Re-run x-pack/qa/fips-approved-probe.rb and update BCFIPS_REGISTERED when jars
#   are upgraded — a patch bump may add or remove approved algorithms.
#   Enforcement is sole-enforcement: C:HYBRID mode means the BCFIPS provider does
#   not refuse non-approved algorithms at the JCE level (confirmed by
#   x-pack/qa/fips-hybrid-check.rb).  There is no provider backstop.
#   Deliberate boundary exceptions (not routed through check!):
#     - HMAC-SHA-1 is permitted for :hmac — explicitly approved per SP 800-131A rev2.
#     - SecureRandom.uuid / UUID generation — not a governed crypto operation.
#     - Non-security digests used for protocol checksums or dedup (S3 Content-MD5,
#       GCS dedup, file-identity fingerprinting) — protocol contracts, not security
#       operations; routing them here risks a tightening breaking a protocol.
#       Each such site carries an inline comment explaining the exception.
#
# OUT OF SCOPE — do NOT route these through check!:
#   - SecureRandom.uuid / UUID generation (see above).
#   - Non-security digest uses (see above).  Leave an inline comment at each site.

require "set"
require "logstash/settings"

module LogStash
  module FIPS
    # Provider floor: algorithms registered by BCFIPS 2.0.1 under
    # -Dorg.bouncycastle.fips.approved_only=true.
    # Source: x-pack/qa/fips-approved-probe.rb.
    # This is NOT the policy — see POLICY below for approved uses.
    BCFIPS_REGISTERED = {
      "MessageDigest"    => %w[SHA-1 SHA-224 SHA-256 SHA-384 SHA-512
                                SHA-512/224 SHA-512/256
                                SHA3-224 SHA3-256 SHA3-384 SHA3-512].to_set.freeze,
      "Mac"              => %w[HmacSHA1 HmacSHA224 HmacSHA256 HmacSHA384 HmacSHA512
                                HmacSHA3-256 HmacSHA3-384 HmacSHA3-512].to_set.freeze,
      "Cipher"           => %w[DESede/CBC/PKCS5Padding
                                AES/CBC/PKCS5Padding AES/GCM/NoPadding
                                AES/CTR/NoPadding AES/OFB/NoPadding
                                AES/CFB/NoPadding].to_set.freeze,
      "Signature"        => %w[SHA1withRSA SHA1withDSA
                                SHA256withRSA SHA256withECDSA SHA256withDSA SHA256withRSA/PSS
                                SHA384withRSA SHA384withECDSA
                                SHA512withRSA SHA512withECDSA].to_set.freeze,
      "SecretKeyFactory" => %w[PBKDF2WithHmacSHA1 PBKDF2WithHmacSHA256
                                PBKDF2WithHmacSHA384 PBKDF2WithHmacSHA512
                                scrypt].to_set.freeze,
      "KeyGenerator"     => %w[AES DESede HmacSHA1 HmacSHA256 HmacSHA512].to_set.freeze,
      # "DEFAULT" is the BCFIPS JCE SecureRandom service name (CTR_DRBG internally,
      # SP 800-90A).  It is not a generic fallback string — do not gate non-BCFIPS
      # "default" config values through :rng.
      "SecureRandom"     => %w[DEFAULT NONCEANDIV].to_set.freeze,
    }.freeze

    # Use-aware approved-algorithm policy.
    # Keys: use-category symbols accepted by check!
    # Values: Sets of canonical algorithm names (the same casing used in ALIASES).
    #
    # Invariant: every member of every set here must have a corresponding entry in
    # ALIASES (either explicit or auto-generated via ALIAS_EXTRAS below) so that
    # callers passing any reasonable casing reach the correct canonical form.
    # The spec enforces this with a round-trip test.
    POLICY = {
      # Security-sensitive digest operations.  SHA-1 excluded: registered by BCFIPS
      # but not approved for new security digest use under FIPS 140-3.
      :digest_security => %w[
        SHA-224 SHA-256 SHA-384 SHA-512
        SHA-512/224 SHA-512/256
        SHA3-224 SHA3-256 SHA3-384 SHA3-512
      ].to_set.freeze,

      # HMAC construction.  Both digest-name ("sha256") and full-HMAC-name
      # ("HmacSHA256", "hmacsha256") inputs are accepted — the ALIASES table maps
      # all forms to the bare digest name used here.
      # HMAC-SHA-1 is explicitly included: HMAC-SHA-1's security does not depend
      # on SHA-1 collision resistance; it remains approved per SP 800-131A rev2.
      # This is a deliberate policy decision, not an inherited BCFIPS default.
      :hmac => %w[
        SHA-1 SHA-224 SHA-256 SHA-384 SHA-512
        SHA3-256 SHA3-384 SHA3-512
      ].to_set.freeze,

      # Symmetric encryption.  DESede excluded (140-3 target; see module comment).
      # OFB and CFB: operation-level confirmed approved under BCFIPS 2.0.1
      # approved_only=true.  AES/CFB/NoPadding resolves to CFB128 (full-block
      # feedback) — the JCE default when no feedback width is specified — which
      # is what SNMPv3 AES privacy (RFC 3826) requires.
      # Pass the full JCE mode string or a recognised shorthand — see ALIASES.
      :cipher => %w[
        AES/CBC/PKCS5Padding AES/GCM/NoPadding AES/CTR/NoPadding
        AES/OFB/NoPadding AES/CFB/NoPadding
      ].to_set.freeze,

      # Digital signatures.  SHA-1 and DSA excluded (see module comment).
      # EdDSA absent from BCFIPS 2.0.1 entirely.
      :signature => %w[
        SHA256withRSA SHA256withECDSA SHA256withRSA/PSS
        SHA384withRSA SHA384withECDSA
        SHA512withRSA SHA512withECDSA
      ].to_set.freeze,

      # Key derivation.  PBKDF2 and scrypt approved with conformant parameters
      # (password >= 112 bits).  bcrypt absent from BCFIPS.
      # "PBKDF2" alone normalises to PBKDF2WithHmacSHA256 via ALIASES.
      :kdf => %w[
        PBKDF2WithHmacSHA1 PBKDF2WithHmacSHA256
        PBKDF2WithHmacSHA384 PBKDF2WithHmacSHA512
        scrypt
      ].to_set.freeze,

      # Random number generation.  "DEFAULT" is the BCFIPS JCE SecureRandom name.
      :rng => %w[DEFAULT NONCEANDIV].to_set.freeze,
    }.freeze

    APPROVED_ALTERNATIVES = {
      :digest_security => "SHA-256, SHA-384, SHA-512, or a SHA-3 variant",
      :hmac            => "SHA-1 (HMAC-SHA-1), SHA-256, SHA-384, or SHA-512",
      :cipher          => "AES/GCM/NoPadding, AES/CBC/PKCS5Padding, AES/CTR/NoPadding, AES/OFB/NoPadding, or AES/CFB/NoPadding",
      :signature       => "SHA256withRSA, SHA384withRSA, SHA512withRSA, " \
                          "SHA256withECDSA, SHA384withECDSA, SHA512withECDSA, " \
                          "or SHA256withRSA/PSS",
      :kdf             => "PBKDF2WithHmacSHA256, PBKDF2WithHmacSHA512, or scrypt " \
                          "(password must be >= 112 bits)",
      :rng             => "DEFAULT or NONCEANDIV (BCFIPS SP 800-90A DRBG service names)",
    }.freeze

    # Explicit alias entries: downcased caller input → canonical POLICY name.
    #
    # For :hmac, both the digest name ("sha1") and the full HMAC JCE name
    # ("hmacsha1", "hmac-sha1") map to the bare digest canonical form ("SHA-1")
    # so that both input styles converge on the same POLICY[:hmac] set.
    #
    # Entries here cover alternate spellings only.  Every POLICY member's own
    # canonical name is additionally auto-registered at module load (see
    # ALIASES below) so that callers passing exact canonical strings always work
    # regardless of casing — no manual alias entry required for canonical names.
    ALIAS_EXTRAS = {
      # ── SHA-1 ──────────────────────────────────────────────────────────────
      "sha1"                    => "SHA-1",
      "sha-1"                   => "SHA-1",
      # ── SHA-2 ──────────────────────────────────────────────────────────────
      "sha224"                  => "SHA-224",
      "sha-224"                 => "SHA-224",
      "sha256"                  => "SHA-256",
      "sha-256"                 => "SHA-256",
      "sha384"                  => "SHA-384",
      "sha-384"                 => "SHA-384",
      "sha512"                  => "SHA-512",
      "sha-512"                 => "SHA-512",
      "sha512/224"              => "SHA-512/224",
      "sha-512/224"             => "SHA-512/224",
      "sha512/256"              => "SHA-512/256",
      "sha-512/256"             => "SHA-512/256",
      # ── SHA-3 ──────────────────────────────────────────────────────────────
      "sha3-224"                => "SHA3-224",
      "sha3224"                 => "SHA3-224",
      "sha3-256"                => "SHA3-256",
      "sha3256"                 => "SHA3-256",
      "sha3-384"                => "SHA3-384",
      "sha3384"                 => "SHA3-384",
      "sha3-512"                => "SHA3-512",
      "sha3512"                 => "SHA3-512",
      # ── MD5 ────────────────────────────────────────────────────────────────
      "md5"                     => "MD5",
      # ── AES (bare — no mode, not in any POLICY set) ─────────────────────
      "aes"                     => "AES",
      "aes-128"                 => "AES",
      "aes-192"                 => "AES",
      "aes-256"                 => "AES",
      "aes128"                  => "AES",
      "aes192"                  => "AES",
      "aes256"                  => "AES",
      # ── AES with mode shorthands ────────────────────────────────────────
      "aes/gcm"                 => "AES/GCM/NoPadding",
      "aes/gcm/nopadding"       => "AES/GCM/NoPadding",
      "aes/cbc"                 => "AES/CBC/PKCS5Padding",
      "aes/cbc/pkcs5padding"    => "AES/CBC/PKCS5Padding",
      "aes/cbc/pkcs7padding"    => "AES/CBC/PKCS5Padding",
      "aes/ctr"                 => "AES/CTR/NoPadding",
      "aes/ctr/nopadding"       => "AES/CTR/NoPadding",
      "aes/ofb"                 => "AES/OFB/NoPadding",
      "aes/ofb/nopadding"       => "AES/OFB/NoPadding",
      "aes/cfb"                 => "AES/CFB/NoPadding",
      "aes/cfb/nopadding"       => "AES/CFB/NoPadding",
      # ── OpenSSL-style cipher names (logstash-filter-cipher) ─────────────
      # Approved: map to the canonical POLICY[:cipher] form.
      "aes-128-cbc"             => "AES/CBC/PKCS5Padding",
      "aes-192-cbc"             => "AES/CBC/PKCS5Padding",
      "aes-256-cbc"             => "AES/CBC/PKCS5Padding",
      "aes-128-gcm"             => "AES/GCM/NoPadding",
      "aes-192-gcm"             => "AES/GCM/NoPadding",
      "aes-256-gcm"             => "AES/GCM/NoPadding",
      "aes-128-ctr"             => "AES/CTR/NoPadding",
      "aes-192-ctr"             => "AES/CTR/NoPadding",
      "aes-256-ctr"             => "AES/CTR/NoPadding",
      "aes-128-ofb"             => "AES/OFB/NoPadding",
      "aes-192-ofb"             => "AES/OFB/NoPadding",
      "aes-256-ofb"             => "AES/OFB/NoPadding",
      "aes-128-cfb"             => "AES/CFB/NoPadding",
      "aes-192-cfb"             => "AES/CFB/NoPadding",
      "aes-256-cfb"             => "AES/CFB/NoPadding",
      # Non-approved: map to a non-POLICY canonical so check! rejects them.
      # ECB is not approved for confidentiality even though it is AES.
      "aes-128-ecb"             => "AES/ECB/NoPadding",
      "aes-192-ecb"             => "AES/ECB/NoPadding",
      "aes-256-ecb"             => "AES/ECB/NoPadding",
      # OpenSSL DES / 3DES names
      "des-cbc"                 => "DES/CBC/PKCS5Padding",
      "des-ede3-cbc"            => "DESede/CBC/PKCS5Padding",
      "des-ede-cbc"             => "DESede/CBC/PKCS5Padding",
      # OpenSSL stream / other cipher names
      "rc4-40"                  => "RC4",
      "bf-cbc"                  => "Blowfish/CBC",
      "bf-ecb"                  => "Blowfish/ECB",
      # ── DES / 3DES ──────────────────────────────────────────────────────
      "des"                     => "DES",
      "3des"                    => "3DES",
      "tripledes"               => "3DES",
      "triple-des"              => "3DES",
      "desede"                  => "DESede/CBC/PKCS5Padding",
      "des-ede"                 => "DESede/CBC/PKCS5Padding",
      "desede/cbc/pkcs5padding" => "DESede/CBC/PKCS5Padding",
      "desede/cbc"              => "DESede/CBC/PKCS5Padding",
      # ── Other block / stream ciphers ────────────────────────────────────
      "rc4"                     => "RC4",
      "arcfour"                 => "RC4",
      "blowfish"                => "Blowfish",
      "camellia"                => "Camellia",
      "idea"                    => "IDEA",
      "chacha20"                => "ChaCha20",
      "chacha20-poly1305"       => "ChaCha20-Poly1305",
      # ── Signature ───────────────────────────────────────────────────────
      "md5withrsa"              => "MD5withRSA",
      "sha1withrsa"             => "SHA1withRSA",
      "sha-1withrsa"            => "SHA1withRSA",
      "sha1withdsa"             => "SHA1withDSA",
      "sha256withrsa"           => "SHA256withRSA",
      "sha-256withrsa"          => "SHA256withRSA",
      "sha256withecdsa"         => "SHA256withECDSA",
      "sha-256withecdsa"        => "SHA256withECDSA",
      "sha256withdsa"           => "SHA256withDSA",
      "sha256withrsa/pss"       => "SHA256withRSA/PSS",
      "sha-256withrsa/pss"      => "SHA256withRSA/PSS",
      "sha384withrsa"           => "SHA384withRSA",
      "sha-384withrsa"          => "SHA384withRSA",
      "sha384withecdsa"         => "SHA384withECDSA",
      "sha-384withecdsa"        => "SHA384withECDSA",
      "sha512withrsa"           => "SHA512withRSA",
      "sha-512withrsa"          => "SHA512withRSA",
      "sha512withecdsa"         => "SHA512withECDSA",
      "sha-512withecdsa"        => "SHA512withECDSA",
      # ── HMAC — both digest-name and full-HMAC-name → digest namespace ───
      # POLICY[:hmac] uses bare digest names.  Full HMAC names also map here
      # so (algorithm: "HmacSHA256", use: :hmac) and (algorithm: "sha256",
      # use: :hmac) both resolve to "SHA-256" and pass the same policy check.
      "hmacmd5"                 => "MD5",
      "hmac-md5"                => "MD5",
      "hmacsha1"                => "SHA-1",
      "hmac-sha1"               => "SHA-1",
      "hmacsha224"              => "SHA-224",
      "hmac-sha224"             => "SHA-224",
      "hmacsha256"              => "SHA-256",
      "hmac-sha256"             => "SHA-256",
      "hmacsha384"              => "SHA-384",
      "hmac-sha384"             => "SHA-384",
      "hmacsha512"              => "SHA-512",
      "hmac-sha512"             => "SHA-512",
      "hmacsha3-256"            => "SHA3-256",
      "hmac-sha3-256"           => "SHA3-256",
      "hmacsha3-384"            => "SHA3-384",
      "hmac-sha3-384"           => "SHA3-384",
      "hmacsha3-512"            => "SHA3-512",
      "hmac-sha3-512"           => "SHA3-512",
      # ── KDF ─────────────────────────────────────────────────────────────
      "pbkdf2"                  => "PBKDF2WithHmacSHA256",
      "pbkdf2withhmacsha1"      => "PBKDF2WithHmacSHA1",
      "pbkdf2withhmacsha256"    => "PBKDF2WithHmacSHA256",
      "pbkdf2withhmacsha384"    => "PBKDF2WithHmacSHA384",
      "pbkdf2withhmacsha512"    => "PBKDF2WithHmacSHA512",
      "bcrypt"                  => "bcrypt",
      "scrypt"                  => "scrypt",
      # ── RNG ─────────────────────────────────────────────────────────────
      "default"                 => "DEFAULT",
      "nonceandiv"              => "NONCEANDIV",
      "sha1prng"                => "SHA1PRNG",
      "nativeprng"              => "NativePRNG",
    }.freeze

    # Full alias map: ALIAS_EXTRAS plus auto-generated reverse entries for every
    # canonical name in every POLICY set (downcased → canonical).  This guarantees
    # every POLICY member is reachable by its own exact name in any casing without
    # requiring a manual alias entry — adding a new algorithm to POLICY is sufficient.
    ALIASES = begin
      auto = {}
      POLICY.each_value do |set|
        set.each { |canonical| auto[canonical.downcase] = canonical }
      end
      # ALIAS_EXTRAS wins over auto-generated entries when they differ
      # (e.g. "sha256" → "SHA-256" rather than auto "sha256" → "SHA256").
      auto.merge(ALIAS_EXTRAS).freeze
    end

    module_function

    # Returns true when fips_mode.enabled is set to true in LogStash::SETTINGS.
    # Returns false if the setting is not yet registered, so early calls before
    # environment.rb loads do not raise.
    #
    # We read an explicit operator setting rather than inferring from BCFIPS
    # provider presence: in C:HYBRID mode the provider is loaded but approved_only
    # is off, so provider presence does not encode operator intent.
    def enabled?
      return false unless LogStash::SETTINGS.registered?("fips_mode.enabled")
      LogStash::SETTINGS.get("fips_mode.enabled")
    end

    # Checks whether +algorithm+ is approved for +use+ under FIPS 140-3.
    #
    # No-op when fips_mode.enabled is false — non-FIPS deployments are
    # completely unaffected.
    #
    # When FIPS is enabled and the algorithm is not approved, raises
    # LogStash::ConfigurationError naming the algorithm, the use, and
    # approved alternatives.
    #
    # @param algorithm [String] algorithm name — case-insensitive, common aliases
    #   accepted.  For :hmac, pass either the digest name ("sha256") or the full
    #   HMAC JCE name ("HmacSHA256") — both resolve correctly.  For :cipher,
    #   pass the full JCE mode string ("AES/GCM/NoPadding") or a shorthand.
    # @param use [Symbol] :digest_security | :hmac | :cipher | :signature |
    #   :kdf | :rng
    # @raise [LogStash::ConfigurationError] when FIPS-enabled and not approved
    # @return [nil]
    def check!(algorithm:, use:)
      return unless enabled?

      table = POLICY.fetch(use) do
        raise ArgumentError, "Unknown FIPS use category: #{use.inspect}. " \
                             "Valid: #{POLICY.keys.map(&:inspect).join(", ")}"
      end

      canonical = normalize(algorithm)

      unless table.include?(canonical)
        alternatives = APPROVED_ALTERNATIVES.fetch(use, "see FIPS policy documentation")
        raise LogStash::ConfigurationError,
              "FIPS policy violation: #{algorithm.inspect} is not approved for " \
              "#{use} use under FIPS 140-3. " \
              "Approved alternatives: #{alternatives}."
      end

      nil
    end

    # Returns the canonical algorithm name for +algorithm+.
    # Downcases and strips the input, looks it up in ALIASES, falls back to
    # the downcased-stripped form.  All POLICY set members are reachable via
    # ALIASES (either through ALIAS_EXTRAS or the auto-generated reverse entries).
    def normalize(algorithm)
      key = algorithm.to_s.downcase.strip
      ALIASES.fetch(key, key)
    end
    module_function :normalize
    private :normalize
  end
end
