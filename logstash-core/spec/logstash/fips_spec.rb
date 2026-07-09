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

require "spec_helper"
require "logstash/fips"

describe LogStash::FIPS do
  # Helper: temporarily set fips_mode.enabled without touching global state permanently.
  def with_fips_enabled(value)
    LogStash::SETTINGS.set("fips_mode.enabled", value)
    yield
  ensure
    LogStash::SETTINGS.set("fips_mode.enabled", false)
  end

  # ── STRUCTURAL INVARIANT ────────────────────────────────────────────────────
  # Every canonical name in every POLICY set must round-trip through normalize
  # back to itself.  If this fails, the entry is unreachable — check!(algorithm:
  # <that name>, use: <category>) would raise a false FIPS violation.
  describe "POLICY round-trip invariant" do
    LogStash::FIPS::POLICY.each do |use, set|
      set.each do |canonical|
        it "#{canonical.inspect} in :#{use} round-trips through normalize" do
          expect(LogStash::FIPS.send(:normalize, canonical)).to eq(canonical)
        end
      end
    end
  end

  # ── enabled? ────────────────────────────────────────────────────────────────
  describe ".enabled?" do
    it "returns false by default" do
      expect(described_class.enabled?).to be false
    end

    it "returns true when fips_mode.enabled is set" do
      with_fips_enabled(true) do
        expect(described_class.enabled?).to be true
      end
    end

    it "returns false when setting is unregistered rather than raising" do
      allow(LogStash::SETTINGS).to receive(:registered?).with("fips_mode.enabled").and_return(false)
      expect(described_class.enabled?).to be false
    end
  end

  # ── check! no-op when disabled ──────────────────────────────────────────────
  describe ".check! when FIPS is disabled" do
    it "is a no-op for DES" do
      expect { described_class.check!(algorithm: "DES", use: :cipher) }.not_to raise_error
    end

    it "is a no-op for MD5" do
      expect { described_class.check!(algorithm: "MD5", use: :digest_security) }.not_to raise_error
    end

    it "is a no-op for RC4" do
      expect { described_class.check!(algorithm: "RC4", use: :cipher) }.not_to raise_error
    end

    it "returns nil" do
      expect(described_class.check!(algorithm: "SHA-256", use: :digest_security)).to be_nil
    end
  end

  # ── check! enforcement when enabled ─────────────────────────────────────────
  describe ".check! when FIPS is enabled" do
    # ── :digest_security ────────────────────────────────────────────────────
    context ":digest_security" do
      it "allows SHA-256 (canonical)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA-256", use: :digest_security) }.not_to raise_error
        end
      end

      it "allows SHA-256 via lowercase input" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha256", use: :digest_security) }.not_to raise_error
        end
      end

      it "allows SHA-256 via sha-256 alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha-256", use: :digest_security) }.not_to raise_error
        end
      end

      it "allows SHA-512" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA-512", use: :digest_security) }.not_to raise_error
        end
      end

      it "allows SHA3-256 (canonical)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA3-256", use: :digest_security) }.not_to raise_error
        end
      end

      it "allows SHA3-256 via sha3-256 alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha3-256", use: :digest_security) }.not_to raise_error
        end
      end

      it "rejects MD5" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "MD5", use: :digest_security) }
            .to raise_error(LogStash::ConfigurationError, /MD5.*not approved.*digest_security/i)
        end
      end

      it "rejects MD5 via lowercase alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "md5", use: :digest_security) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "rejects SHA-1 for security digest use" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA-1", use: :digest_security) }
            .to raise_error(LogStash::ConfigurationError, /SHA-1.*not approved.*digest_security/i)
        end
      end

      it "rejects SHA-1 via sha1 alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha1", use: :digest_security) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "includes approved alternatives in the error message" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "MD5", use: :digest_security) }
            .to raise_error(LogStash::ConfigurationError, /SHA-256/)
        end
      end
    end

    # ── :hmac ────────────────────────────────────────────────────────────────
    context ":hmac" do
      it "allows SHA-256 via digest name" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha256", use: :hmac) }.not_to raise_error
        end
      end

      it "allows SHA-256 via full HMAC name HmacSHA256" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "HmacSHA256", use: :hmac) }.not_to raise_error
        end
      end

      it "allows SHA-256 via lowercase hmacsha256" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "hmacsha256", use: :hmac) }.not_to raise_error
        end
      end

      it "allows SHA-256 via hmac-sha256 alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "hmac-sha256", use: :hmac) }.not_to raise_error
        end
      end

      it "allows SHA-1 for HMAC use (HMAC-SHA-1 is approved per SP 800-131A rev2)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha1", use: :hmac) }.not_to raise_error
        end
      end

      it "allows SHA-1 via HmacSHA1 full name" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "HmacSHA1", use: :hmac) }.not_to raise_error
        end
      end

      it "rejects HMAC-MD5 via full name" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "HmacMD5", use: :hmac) }
            .to raise_error(LogStash::ConfigurationError, /HmacMD5.*not approved.*hmac/i)
        end
      end

      it "rejects HMAC-MD5 via hmacmd5 alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "hmacmd5", use: :hmac) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "rejects HMAC-MD5 via hmac-md5 alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "hmac-md5", use: :hmac) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end
    end

    # ── :cipher ──────────────────────────────────────────────────────────────
    context ":cipher" do
      it "allows AES/GCM/NoPadding (canonical)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "AES/GCM/NoPadding", use: :cipher) }.not_to raise_error
        end
      end

      it "allows AES/GCM/NoPadding via lowercase aes/gcm/nopadding alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "aes/gcm/nopadding", use: :cipher) }.not_to raise_error
        end
      end

      it "allows AES/GCM via shorthand alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "aes/gcm", use: :cipher) }.not_to raise_error
        end
      end

      it "allows AES/CBC/PKCS5Padding" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "AES/CBC/PKCS5Padding", use: :cipher) }.not_to raise_error
        end
      end

      it "rejects DES" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "DES", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError, /DES.*not approved.*cipher/i)
        end
      end

      it "rejects DES via lowercase" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "des", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "rejects DESede (3DES) — excluded even though BCFIPS_REGISTERED contains it" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "DESede/CBC/PKCS5Padding", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError, /not approved.*cipher/i)
        end
      end

      it "rejects DESede via desede alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "desede", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "rejects DESede via 3des alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "3des", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "rejects RC4" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "RC4", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "rejects Blowfish" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "Blowfish", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "allows AES/OFB/NoPadding (canonical, operation-level approved)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "AES/OFB/NoPadding", use: :cipher) }.not_to raise_error
        end
      end

      it "allows AES/CFB/NoPadding (canonical, CFB128, SNMPv3-aligned)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "AES/CFB/NoPadding", use: :cipher) }.not_to raise_error
        end
      end

      it "allows aes-256-ofb (OpenSSL-style, FIPS on)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "aes-256-ofb", use: :cipher) }.not_to raise_error
        end
      end

      it "allows aes-256-cfb (OpenSSL-style, FIPS on)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "aes-256-cfb", use: :cipher) }.not_to raise_error
        end
      end

      # collectd and SNMP pass uppercase OpenSSL-style names — confirm downcase-then-alias works
      it "allows AES-256-OFB (uppercase OpenSSL, as collectd/SNMP emit it)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "AES-256-OFB", use: :cipher) }.not_to raise_error
        end
      end

      it "allows AES-256-CFB (uppercase OpenSSL, as collectd/SNMP emit it)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "AES-256-CFB", use: :cipher) }.not_to raise_error
        end
      end

      # Regression guard: adding OFB/CFB must not loosen ECB or DES/3DES
      it "still rejects AES/ECB (ECB not approved for confidentiality)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "aes-256-ecb", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "still rejects DES after OFB/CFB addition" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "DES", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "still rejects 3DES (DESede) after OFB/CFB addition" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "3des", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end
    end

    # ── OpenSSL-style cipher name aliases (logstash-filter-cipher) ───────────
    # These test the ALIASES entries added for OpenSSL-style spellings.  They are
    # not in POLICY directly (input aliases only), so the round-trip invariant does
    # not cover them — explicit cases are required.
    context ":cipher — OpenSSL-style names (FIPS on)" do
      {
        "aes-256-cbc"  => false,
        "aes-128-cbc"  => false,
        "aes-192-cbc"  => false,
        "aes-128-gcm"  => false,
        "aes-256-gcm"  => false,
        "aes-256-ctr"  => false,
        "aes-256-ofb"  => false,
        "aes-256-cfb"  => false,
        "aes-256-GCM"  => false,  # case-insensitive
        "aes-256-ecb"  => true,
        "des-cbc"      => true,
        "des-ede3-cbc" => true,
      }.each do |cipher, should_raise|
        if should_raise
          it "rejects #{cipher.inspect} under FIPS" do
            with_fips_enabled(true) do
              expect { described_class.check!(algorithm: cipher, use: :cipher) }
                .to raise_error(LogStash::ConfigurationError)
            end
          end
        else
          it "allows #{cipher.inspect} under FIPS" do
            with_fips_enabled(true) do
              expect { described_class.check!(algorithm: cipher, use: :cipher) }.not_to raise_error
            end
          end
        end
      end
    end

    context ":cipher — OpenSSL-style names (FIPS off)" do
      %w[aes-256-cbc aes-128-gcm aes-256-ctr aes-256-ecb des-cbc des-ede3-cbc].each do |cipher|
        it "is a no-op for #{cipher.inspect} when FIPS is disabled" do
          with_fips_enabled(false) do
            expect { described_class.check!(algorithm: cipher, use: :cipher) }.not_to raise_error
          end
        end
      end
    end

    # ── :signature ───────────────────────────────────────────────────────────
    context ":signature" do
      it "allows SHA256withRSA (canonical)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA256withRSA", use: :signature) }.not_to raise_error
        end
      end

      it "allows SHA256withRSA via lowercase sha256withrsa alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha256withrsa", use: :signature) }.not_to raise_error
        end
      end

      it "allows SHA256withECDSA" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA256withECDSA", use: :signature) }.not_to raise_error
        end
      end

      it "allows SHA256withRSA/PSS" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA256withRSA/PSS", use: :signature) }.not_to raise_error
        end
      end

      it "allows SHA256withRSA/PSS via lowercase alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha256withrsa/pss", use: :signature) }.not_to raise_error
        end
      end

      it "rejects SHA1withRSA — SHA-1 signatures not approved under 140-3" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA1withRSA", use: :signature) }
            .to raise_error(LogStash::ConfigurationError, /SHA1withRSA.*not approved.*signature/i)
        end
      end

      it "rejects SHA1withRSA via lowercase alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha1withrsa", use: :signature) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      it "rejects SHA256withDSA — DSA withdrawn under FIPS 186-5" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA256withDSA", use: :signature) }
            .to raise_error(LogStash::ConfigurationError, /SHA256withDSA.*not approved.*signature/i)
        end
      end

      it "rejects MD5withRSA" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "MD5withRSA", use: :signature) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end

      # SHA-1 rejected for :signature but accepted for :hmac — the use parameter is load-bearing
      it "SHA-1 rejected for :signature but accepted for :hmac" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "sha1", use: :signature) }
            .to raise_error(LogStash::ConfigurationError)
          expect { described_class.check!(algorithm: "sha1", use: :hmac) }.not_to raise_error
        end
      end
    end

    # ── :kdf ─────────────────────────────────────────────────────────────────
    context ":kdf" do
      it "allows PBKDF2WithHmacSHA256 (canonical)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "PBKDF2WithHmacSHA256", use: :kdf) }.not_to raise_error
        end
      end

      it "allows PBKDF2WithHmacSHA256 via pbkdf2 shorthand" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "pbkdf2", use: :kdf) }.not_to raise_error
        end
      end

      it "allows scrypt" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "scrypt", use: :kdf) }.not_to raise_error
        end
      end

      it "rejects bcrypt" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "bcrypt", use: :kdf) }
            .to raise_error(LogStash::ConfigurationError, /bcrypt.*not approved.*kdf/i)
        end
      end
    end

    # ── :rng ─────────────────────────────────────────────────────────────────
    context ":rng" do
      it "allows DEFAULT (BCFIPS CTR_DRBG service name)" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "DEFAULT", use: :rng) }.not_to raise_error
        end
      end

      it "allows DEFAULT via lowercase alias" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "default", use: :rng) }.not_to raise_error
        end
      end

      it "rejects SHA1PRNG" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "SHA1PRNG", use: :rng) }
            .to raise_error(LogStash::ConfigurationError, /SHA1PRNG.*not approved.*rng/i)
        end
      end

      it "rejects NativePRNG" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "NativePRNG", use: :rng) }
            .to raise_error(LogStash::ConfigurationError)
        end
      end
    end

    # ── error messages ────────────────────────────────────────────────────────
    context "error message content" do
      it "names the algorithm" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "DES", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError, /"DES"/)
        end
      end

      it "names the use category" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "DES", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError, /cipher/)
        end
      end

      it "names approved alternatives" do
        with_fips_enabled(true) do
          expect { described_class.check!(algorithm: "DES", use: :cipher) }
            .to raise_error(LogStash::ConfigurationError, /AES/)
        end
      end
    end

    # ── unknown use category ──────────────────────────────────────────────────
    it "raises ArgumentError for an unknown use category" do
      with_fips_enabled(true) do
        expect { described_class.check!(algorithm: "AES", use: :unknown_use) }
          .to raise_error(ArgumentError, /unknown_use/)
      end
    end

    # ── end-to-end: enabled path actually enforces ───────────────────────────
    # Belt-and-suspenders: confirm that flipping the setting to true causes a
    # real violation to raise.  The individual category tests above also cover
    # this, but an explicit "it enforces when enabled" test makes the intent
    # unambiguous and fails immediately if enabled? ever stops reading the setting.
    it "enforces policy when fips_mode.enabled is true" do
      with_fips_enabled(true) do
        expect(described_class.enabled?).to be true
        expect { described_class.check!(algorithm: "DES", use: :cipher) }
          .to raise_error(LogStash::ConfigurationError)
      end
    end

    it "is a no-op for the same call when fips_mode.enabled is false" do
      with_fips_enabled(false) do
        expect(described_class.enabled?).to be false
        expect { described_class.check!(algorithm: "DES", use: :cipher) }.not_to raise_error
      end
    end
  end

  # ── normalize visibility ─────────────────────────────────────────────────────
  # `module_function :normalize; private :normalize` creates a public module-level
  # copy (so check! can call it) and a private instance-method copy (so including
  # classes cannot call it directly).  In JRuby, `private` after `module_function`
  # only suppresses the instance-method side — LogStash::FIPS.normalize is still
  # reachable but is an internal implementation detail, not a promised API.
  describe "normalize" do
    it "is private for objects that include the module" do
      includer = Class.new { include LogStash::FIPS }.new
      expect { includer.normalize("sha256") }.to raise_error(NoMethodError)
    end

    it "is exercised internally by check! (alias resolution works end-to-end)" do
      with_fips_enabled(true) do
        # "sha256" → normalize → "SHA-256" → in POLICY[:digest_security] → no raise
        expect { described_class.check!(algorithm: "sha256", use: :digest_security) }.not_to raise_error
        # "sha1" → normalize → "SHA-1" → not in POLICY[:digest_security] → raises
        expect { described_class.check!(algorithm: "sha1", use: :digest_security) }
          .to raise_error(LogStash::ConfigurationError)
      end
    end
  end
end
