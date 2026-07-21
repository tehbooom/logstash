#!/usr/bin/env ruby
# Empirical probe: what does -Dorg.bouncycastle.fips.approved_only=true
# actually do in Logstash's JRuby environment?
#
# Run from repo root:
#
#   vendor/jruby/bin/jruby \
#     -J-Dorg.bouncycastle.fips.approved_only=true \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.1.jar:x-pack/build/fips-provider-jars/bctls-fips-2.0.22.jar:x-pack/build/fips-provider-jars/bcutil-fips-2.0.5.jar:x-pack/build/fips-provider-jars/bcpkix-fips-2.0.7.jar" \
#     -J-Djruby.openssl.provider.register=false \
#     x-pack/qa/fips-approved-only-probe.rb
#
# Tests four layers independently and emits a result table.

require "java"

java_import "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"
java_import "org.bouncycastle.crypto.CryptoServicesRegistrar"

BCFIPS = BouncyCastleFipsProvider.new
java.security.Security.insertProviderAt(BCFIPS, 1)

puts "=== SETUP ==="
puts "Providers: #{java.security.Security.getProviders.map(&:getName).join(", ")}"
puts "BCFIPS provider info: #{BCFIPS.getInfo}"
puts

results = []  # [layer, call, outcome, note]

# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — Did the JVM flag actually take effect?
# ─────────────────────────────────────────────────────────────────────────────
puts "=== TEST 1: CryptoServicesRegistrar.isInApprovedOnlyMode() ==="
begin
  approved_only = CryptoServicesRegistrar.isInApprovedOnlyMode
  puts "isInApprovedOnlyMode: #{approved_only}"
  if approved_only
    results << ["JVM flag", "isInApprovedOnlyMode()", "true", "Flag active — tests below are meaningful"]
    flag_active = true
  else
    puts "WARNING: Flag is NOT active. -J-Dorg.bouncycastle.fips.approved_only=true did not propagate."
    results << ["JVM flag", "isInApprovedOnlyMode()", "false", "FLAG NOT ACTIVE — tests below are inconclusive"]
    flag_active = false
  end
rescue => e
  puts "ERROR checking flag: #{e.class}: #{e.message}"
  results << ["JVM flag", "isInApprovedOnlyMode()", "ERROR: #{e.class}", e.message.lines.first.chomp]
  flag_active = false
end
puts

# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — JCE-layer DES: should be BLOCKED when approved_only=true
# ─────────────────────────────────────────────────────────────────────────────
puts "=== TEST 2: JCE-layer DES/CBC via BCFIPS provider ==="
begin
  cipher = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", BCFIPS)
  # Attempt init+doFinal to confirm it actually runs
  key_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08].to_java(:byte)
  key = javax.crypto.spec.SecretKeySpec.new(key_bytes, "DES")
  iv  = javax.crypto.spec.IvParameterSpec.new([0]*8.to_java(:byte))
  cipher.init(javax.crypto.Cipher::ENCRYPT_MODE, key, iv)
  ct = cipher.doFinal("hello world!!!!".to_java_bytes)
  puts "DES JCE: ACCEPTED (enc #{ct.length} bytes) — approved_only gate did NOT block JCE layer"
  results << ["JCE (BCFIPS)", "Cipher.getInstance(DES/CBC)", "ACCEPTED", "gate DID NOT block — plugin guards are sole enforcement"]
rescue java.lang.Error => e
  puts "DES JCE: BLOCKED by Error — #{e.class}: #{e.message.lines.first.chomp}"
  results << ["JCE (BCFIPS)", "Cipher.getInstance(DES/CBC)", "BLOCKED (Error)", "#{e.class}"]
rescue java.lang.Exception => e
  puts "DES JCE: BLOCKED by Exception — #{e.class}: #{e.message.lines.first.chomp}"
  results << ["JCE (BCFIPS)", "Cipher.getInstance(DES/CBC)", "BLOCKED (Exception)", "#{e.class}"]
rescue => e
  puts "DES JCE: BLOCKED by Ruby error — #{e.class}: #{e.message.lines.first.chomp}"
  results << ["JCE (BCFIPS)", "Cipher.getInstance(DES/CBC)", "BLOCKED (Ruby)", "#{e.class}"]
end
puts

# ─────────────────────────────────────────────────────────────────────────────
# TEST 3a — JRuby-OpenSSL DES-CBC: does it bypass the provider gate?
# ─────────────────────────────────────────────────────────────────────────────
puts "=== TEST 3a: JRuby-OpenSSL OpenSSL::Cipher.new('des-cbc') ==="
begin
  require "openssl"
  puts "  OpenSSL version: #{OpenSSL::VERSION} / #{OpenSSL::OPENSSL_VERSION}"
  c = OpenSSL::Cipher.new("des-cbc")
  c.encrypt
  c.key = "12345678"
  c.iv  = "12345678"
  ct = c.update("hello world!") + c.final
  puts "des-cbc: ACCEPTED (#{ct.bytesize} bytes) — JRuby-OpenSSL BYPASSES the approved_only gate"
  results << ["JRuby-OpenSSL", "OpenSSL::Cipher.new('des-cbc')", "ACCEPTED", "bypasses BCFIPS approved-only gate — confirms check! necessity"]
rescue OpenSSL::Cipher::CipherError => e
  puts "des-cbc: OpenSSL::Cipher::CipherError — #{e.message}"
  results << ["JRuby-OpenSSL", "OpenSSL::Cipher.new('des-cbc')", "CipherError", e.message.lines.first.chomp]
rescue => e
  puts "des-cbc: #{e.class}: #{e.message.lines.first.chomp}"
  results << ["JRuby-OpenSSL", "OpenSSL::Cipher.new('des-cbc')", "#{e.class}", e.message.lines.first.chomp]
end
puts

# ─────────────────────────────────────────────────────────────────────────────
# TEST 3b — JRuby-OpenSSL HMAC-MD5: does it bypass the provider gate?
# ─────────────────────────────────────────────────────────────────────────────
puts "=== TEST 3b: JRuby-OpenSSL OpenSSL::HMAC.hexdigest(MD5) ==="
begin
  require "openssl"
  digest = OpenSSL::Digest.new("md5")
  result = OpenSSL::HMAC.hexdigest(digest, "key", "data")
  puts "HMAC-MD5: ACCEPTED => #{result} — JRuby-OpenSSL BYPASSES the approved_only gate"
  results << ["JRuby-OpenSSL", "HMAC.hexdigest(MD5, ...)", "ACCEPTED", "bypasses BCFIPS approved-only gate — confirms check! necessity"]
rescue => e
  puts "HMAC-MD5: #{e.class}: #{e.message.lines.first.chomp}"
  results << ["JRuby-OpenSSL", "HMAC.hexdigest(MD5, ...)", "#{e.class}", e.message.lines.first.chomp]
end
puts

# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 — SecureRandom behavior under approved_only=true
# ─────────────────────────────────────────────────────────────────────────────
puts "=== TEST 4: SecureRandom behavior ==="

# 4a: BCFIPS DEFAULT (approved DRBG)
begin
  rng = java.security.SecureRandom.getInstance("DEFAULT", BCFIPS)
  bytes = Java::byte[16].new
  rng.nextBytes(bytes)
  puts "SecureRandom DEFAULT (BCFIPS): OK — #{bytes.to_a.map{|b| "%02x" % b}.join}"
  results << ["SecureRandom", "getInstance('DEFAULT', BCFIPS)", "OK", "approved DRBG works"]
rescue java.lang.Error => e
  puts "SecureRandom DEFAULT: BLOCKED (Error) — #{e.class}: #{e.message.lines.first.chomp}"
  results << ["SecureRandom", "getInstance('DEFAULT', BCFIPS)", "BLOCKED (Error)", e.class.to_s]
rescue => e
  puts "SecureRandom DEFAULT: #{e.class}: #{e.message.lines.first.chomp}"
  results << ["SecureRandom", "getInstance('DEFAULT', BCFIPS)", "#{e.class}", e.message.lines.first.chomp]
end

# 4b: SHA1PRNG — non-approved, expect blocked or fall-through
begin
  rng = java.security.SecureRandom.getInstance("SHA1PRNG")
  bytes = Java::byte[16].new
  rng.nextBytes(bytes)
  puts "SecureRandom SHA1PRNG (JVM): OK — #{bytes.to_a.map{|b| "%02x" % b}.join} — non-BCFIPS provider accepted"
  results << ["SecureRandom", "getInstance('SHA1PRNG') [JVM]", "OK (non-BCFIPS)", "falls through to non-BCFIPS provider"]
rescue java.lang.Error => e
  puts "SecureRandom SHA1PRNG: BLOCKED (Error) — #{e.class}"
  results << ["SecureRandom", "getInstance('SHA1PRNG') [JVM]", "BLOCKED (Error)", e.class.to_s]
rescue => e
  puts "SecureRandom SHA1PRNG: #{e.class}: #{e.message.lines.first.chomp}"
  results << ["SecureRandom", "getInstance('SHA1PRNG') [JVM]", "#{e.class}", e.message.lines.first.chomp]
end

# 4c: Ruby SecureRandom (goes through JRuby, not BCFIPS directly)
begin
  require "securerandom"
  val = SecureRandom.hex(8)
  puts "Ruby SecureRandom.hex: OK — #{val}"
  results << ["JRuby SecureRandom", "SecureRandom.hex(8)", "OK", "Ruby layer works"]
rescue => e
  puts "Ruby SecureRandom.hex: #{e.class}: #{e.message.lines.first.chomp}"
  results << ["JRuby SecureRandom", "SecureRandom.hex(8)", "#{e.class}", e.message.lines.first.chomp]
end
puts

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS TABLE
# ─────────────────────────────────────────────────────────────────────────────
puts "=" * 100
puts "RESULTS TABLE"
puts "=" * 100
fmt = "%-20s | %-42s | %-20s | %s"
puts fmt % ["Layer", "Call", "Outcome", "Conclusion"]
puts "-" * 100
results.each do |row|
  puts fmt % row
end
puts "=" * 100
puts
puts "KEY QUESTION — TEST 3 (JRuby-OpenSSL bypass):"
t3 = results.select { |r| r[0] == "JRuby-OpenSSL" }
if t3.all? { |r| r[2] == "ACCEPTED" }
  puts "  CONFIRMED: JRuby-OpenSSL bypasses the BCFIPS approved_only gate."
  puts "  LogStash::FIPS.check! is the sole enforcement layer for Ruby-layer crypto."
  puts "  The ES-based prediction was CORRECT for the JRuby case."
elsif t3.all? { |r| r[2].start_with?("BLOCKED") }
  puts "  REFUTED: JRuby-OpenSSL is also blocked by approved_only=true."
  puts "  The gate propagates through the JRuby-OpenSSL layer — check! is defence-in-depth."
else
  puts "  MIXED: #{t3.map{|r| "#{r[1]}=>#{r[2]}"}.join(", ")}"
end
