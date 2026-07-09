#!/usr/bin/env ruby
# Probes BCFIPS to determine which JCE algorithms are registered under approved-only mode.
#
# Run from the repo root:
#
#   vendor/jruby/bin/jruby \
#     -J-Dorg.bouncycastle.fips.approved_only=true \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.1.jar:x-pack/build/fips-provider-jars/bctls-fips-2.0.22.jar:x-pack/build/fips-provider-jars/bcutil-fips-2.0.5.jar:x-pack/build/fips-provider-jars/bcpkix-fips-2.0.7.jar" \
#     -J-Djruby.openssl.provider.register=false \
#     x-pack/qa/fips-approved-probe.rb
#
# Emits a BCFIPS_REGISTERED Ruby constant suitable for updating in
# logstash-core/lib/logstash/fips.rb. Re-run when BCFIPS jars are upgraded.
#
# WHY the JVM flag rather than per-thread CryptoServicesRegistrar.setApprovedOnlyMode(true):
#   The per-thread ratchet is one-way — calling setApprovedOnlyMode(false) on a thread
#   that already flipped approved throws FipsUnapprovedOperationError. Running the
#   whole probe process under -Dorg.bouncycastle.fips.approved_only=true avoids
#   that trap: all threads start approved from class-load time.
#
# WHY getInstance is sufficient here (not operation-level):
#   Under -Dorg.bouncycastle.fips.approved_only=true BCFIPS prunes its JCE service
#   table so that non-approved algorithms are simply not registered. getInstance
#   throwing NoSuchAlgorithmException is therefore a reliable "not approved" signal
#   at the registration level. We also run operation-level probes for KDF algorithms
#   (PBKDF2, scrypt) because those have parameter-dependent enforcement — a
#   conformant operation (password >= 112 bits) confirms real-world approvability.
#
# NOTE — this table is the PROVIDER FLOOR, not the policy:
#   BCFIPS_REGISTERED captures "what the provider computes under approved-only mode."
#   LogStash::FIPS::POLICY then narrows this further for use-contextual restrictions:
#   - SHA-1 signatures: registered by BCFIPS for legacy compat; excluded from
#     :signature by policy (FIPS 186-5 / SP 800-131A).
#   - DSA signatures: registered by BCFIPS 2.0.x; excluded by policy (FIPS 186-5
#     withdrew DSA for new signature generation, Feb 2023).
#   - DESede (3DES): registered for FIPS 140-2 legacy compat; excluded from :cipher
#     since we target 140-3.
#   - HMAC-SHA-1: registered and included in :hmac (HMAC-SHA-1 is approved per
#     SP 800-131A rev2; collision resistance of SHA-1 is not a factor for HMAC).

require "java"
java_import "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"

BCFIPS = BouncyCastleFipsProvider.new
java.security.Security.insertProviderAt(BCFIPS, 1)

CANDIDATES = {
  "MessageDigest"    => %w[MD5 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512 SHA-512/224 SHA-512/256
                            SHA3-224 SHA3-256 SHA3-384 SHA3-512],
  "Mac"              => %w[HmacMD5 HmacSHA1 HmacSHA224 HmacSHA256 HmacSHA384 HmacSHA512
                            HmacSHA3-256 HmacSHA3-384 HmacSHA3-512],
  "Cipher"           => %w[DES/CBC/PKCS5Padding DESede/CBC/PKCS5Padding
                            AES/CBC/PKCS5Padding AES/GCM/NoPadding AES/CTR/NoPadding
                            AES/OFB/NoPadding AES/CFB/NoPadding
                            RC4 Blowfish/CBC/PKCS5Padding ChaCha20-Poly1305],
  "Signature"        => %w[MD5withRSA SHA1withRSA SHA1withDSA
                            SHA256withRSA SHA256withECDSA SHA256withDSA SHA256withRSA/PSS
                            SHA384withRSA SHA384withECDSA SHA512withRSA SHA512withECDSA
                            Ed25519 Ed448],
  "SecretKeyFactory" => %w[bcrypt PBKDF2WithHmacSHA1 PBKDF2WithHmacSHA256
                            PBKDF2WithHmacSHA384 PBKDF2WithHmacSHA512 scrypt],
  "KeyGenerator"     => %w[AES DES DESede HmacSHA1 HmacSHA256 HmacSHA512],
  "SecureRandom"     => %w[DEFAULT NONCEANDIV SHA1PRNG NativePRNG],
}.freeze

def probe_get(svc, algo)
  case svc
  when "MessageDigest"    then java.security.MessageDigest.getInstance(algo, BCFIPS)
  when "Mac"              then javax.crypto.Mac.getInstance(algo, BCFIPS)
  when "Cipher"           then javax.crypto.Cipher.getInstance(algo, BCFIPS)
  when "Signature"        then java.security.Signature.getInstance(algo, BCFIPS)
  when "SecretKeyFactory" then javax.crypto.SecretKeyFactory.getInstance(algo, BCFIPS)
  when "KeyGenerator"     then javax.crypto.KeyGenerator.getInstance(algo, BCFIPS)
  when "SecureRandom"     then java.security.SecureRandom.getInstance(algo, BCFIPS)
  end
  :registered
rescue java.lang.Throwable
  :absent
end

# Operation-level confirmation for KDFs: BCFIPS enforces parameter minimums
# (password >= 112 bits) at generateSecret time, not at getInstance.
def probe_kdf_op(algo)
  pw   = "passwordpasswd1".to_java.to_char_array  # 15 chars = 120 bits > 112-bit min
  salt = [0] * 16
  skf  = javax.crypto.SecretKeyFactory.getInstance(algo, BCFIPS)
  if algo == "scrypt"
    skf.generate_secret(org.bouncycastle.jcajce.spec.ScryptKeySpec.new(pw, salt.to_java(:byte), 16384, 8, 1, 256))
  else
    skf.generate_secret(javax.crypto.spec.PBEKeySpec.new(pw, salt.to_java(:byte), 600_000, 256))
  end
  :approved
rescue java.lang.Throwable => e
  :"rejected(#{e.message.to_s.lines.first.chomp.slice(0, 60)})"
end

results = {}
CANDIDATES.each do |svc, algos|
  results[svc] = algos.each_with_object({}) { |a, h| h[a] = probe_get(svc, a) }
end

puts "# Generated by x-pack/qa/fips-approved-probe.rb"
puts "# Provider: #{BCFIPS.getInfo}"
puts "# Probe: JVM -Dorg.bouncycastle.fips.approved_only=true + getInstance"
puts "# KDF entries additionally confirmed at operation level (see probe_kdf_op)."
puts "#"
puts "# This is BCFIPS_REGISTERED (provider floor). Policy narrowing is applied"
puts "# on top in LogStash::FIPS::POLICY — see that file for use-contextual exclusions."
puts

puts "BCFIPS_REGISTERED = {"
results.each do |svc, algos|
  reg  = algos.select { |_, v| v == :registered }.keys
  puts "  # #{svc} — registered: #{reg.join(", ")}"
  puts "  \"#{svc}\" => %w[#{reg.join(" ")}].to_set.freeze,"
end
puts "}.freeze"

puts
puts "# KDF operation-level verification (password=120 bits, conformant params):"
%w[PBKDF2WithHmacSHA1 PBKDF2WithHmacSHA256 PBKDF2WithHmacSHA384 PBKDF2WithHmacSHA512 scrypt].each do |a|
  puts "#   #{a}: #{probe_kdf_op(a)}"
end

puts
puts "# Sanity check — MD5 must be absent (confirms JVM flag was active):"
puts "# MD5 MessageDigest: #{results.dig("MessageDigest", "MD5")}  #{results.dig("MessageDigest", "MD5") == :absent ? "(CORRECT)" : "(WRONG — rerun with -Dorg.bouncycastle.fips.approved_only=true)"}"
