#!/usr/bin/env ruby
# Probe: can jruby-openssl be forced to route OpenSSL::Cipher / HMAC through BCFIPS?
#
# Tests, in order:
#   A) What provider does SecurityHelper actually pick up? (what does provider.register=true register?)
#   B) provider.register=true: does DES/MD5 get blocked?
#   C) provider.register=true + BCFIPS injected first: does DES/MD5 get blocked?
#   D) TLS (SSLContext): does jruby.openssl.ssl.provider=BCJSSE route through BCFIPS?
#   E) Direct JCE with BCFIPS (baseline — proves BCFIPS IS present and blocks)
#
# Run:
#   vendor/jruby/bin/jruby \
#     -J-Dorg.bouncycastle.fips.approved_only=true \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.1.jar:x-pack/build/fips-provider-jars/bctls-fips-2.0.22.jar:x-pack/build/fips-provider-jars/bcutil-fips-2.0.5.jar:x-pack/build/fips-provider-jars/bcpkix-fips-2.0.7.jar" \
#     -J-Djruby.openssl.provider.register=<true|false> \
#     -J-Djruby.openssl.ssl.provider=<BCJSSE|false> \
#     x-pack/qa/fips-jruby-openssl-routing-probe.rb

require "java"

java_import "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"
java_import "org.bouncycastle.crypto.CryptoServicesRegistrar"

BCFIPS = BouncyCastleFipsProvider.new

# ──────────────────────────────────────────────────────────────────────────────
# Setup: show providers BEFORE jruby-openssl loads
# ──────────────────────────────────────────────────────────────────────────────
puts "=== ENVIRONMENT ==="
puts "approved_only flag: #{CryptoServicesRegistrar.isInApprovedOnlyMode}"
puts "provider.register property: #{java.lang.System.getProperty('jruby.openssl.provider.register').inspect}"
puts "ssl.provider property: #{java.lang.System.getProperty('jruby.openssl.ssl.provider').inspect}"
puts "Providers BEFORE openssl load: #{java.security.Security.getProviders.map(&:getName).join(', ')}"
puts "BCFIPS in list? #{java.security.Security.getProviders.any? { |p| p.getName =~ /BCFIPS/ }}"
puts

# ──────────────────────────────────────────────────────────────────────────────
# Load openssl — this triggers SecurityHelper initialization
# ──────────────────────────────────────────────────────────────────────────────
require "openssl"
puts "=== AFTER openssl load ==="
puts "OpenSSL version: #{OpenSSL::VERSION} / #{OpenSSL::OPENSSL_VERSION}"
puts "Providers AFTER openssl load: #{java.security.Security.getProviders.map(&:getName).join(', ')}"
puts

# ──────────────────────────────────────────────────────────────────────────────
# Inspect what SecurityHelper.securityProvider actually is
# ──────────────────────────────────────────────────────────────────────────────
puts "=== SECURITY HELPER INTROSPECTION ==="
begin
  sh_class = java.lang.Class.forName("org.jruby.ext.openssl.SecurityHelper")
  field = sh_class.getDeclaredField("securityProvider")
  field.setAccessible(true)
  actual_provider = field.get(nil)
  if actual_provider
    puts "SecurityHelper.securityProvider: #{actual_provider.getName} (#{actual_provider.getClass.getName})"
    puts "  Is BCFIPS provider? #{actual_provider.is_a?(BouncyCastleFipsProvider)}"
    puts "  Info: #{actual_provider.getInfo rescue 'N/A'}"
    # Check if it has DES cipher
    des_service = actual_provider.getService("Cipher", "DES")
    puts "  DES Cipher service present: #{!des_service.nil?}"
  else
    puts "SecurityHelper.securityProvider: nil (not set)"
  end
rescue => e
  puts "Could not introspect SecurityHelper: #{e.class}: #{e.message}"
end
puts

# ──────────────────────────────────────────────────────────────────────────────
# TEST A: OpenSSL::Cipher DES-CBC with current provider config
# ──────────────────────────────────────────────────────────────────────────────
puts "=== TEST A: OpenSSL::Cipher.new('des-cbc') ==="
begin
  c = OpenSSL::Cipher.new("des-cbc")
  c.encrypt
  c.key = "12345678"
  c.iv  = "12345678"
  ct = c.update("hello world!") + c.final
  puts "RESULT: ACCEPTED (#{ct.bytesize} bytes) — DES succeeded, NOT routed through BCFIPS approved-only"
rescue OpenSSL::Cipher::CipherError => e
  puts "RESULT: OpenSSL::Cipher::CipherError — #{e.message}"
rescue => e
  puts "RESULT: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

# ──────────────────────────────────────────────────────────────────────────────
# TEST B: OpenSSL::HMAC with MD5
# ──────────────────────────────────────────────────────────────────────────────
puts "=== TEST B: OpenSSL::HMAC.hexdigest(MD5) ==="
begin
  result = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("md5"), "key", "data")
  puts "RESULT: ACCEPTED => #{result} — HMAC-MD5 succeeded, NOT routed through BCFIPS approved-only"
rescue => e
  puts "RESULT: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

# ──────────────────────────────────────────────────────────────────────────────
# TEST C: Force-inject BCFIPS as SecurityHelper's provider THEN retry
# (This tests: if we could somehow swap the provider at runtime, would it work?)
# ──────────────────────────────────────────────────────────────────────────────
puts "=== TEST C: Force-inject BCFIPS into SecurityHelper, then retry ==="
begin
  sh_class = java.lang.Class.forName("org.jruby.ext.openssl.SecurityHelper")
  field = sh_class.getDeclaredField("securityProvider")
  field.setAccessible(true)
  old_provider = field.get(nil)
  puts "  Swapping SecurityHelper provider: #{old_provider&.getName} -> BCFIPS"
  field.set(nil, BCFIPS)
  java.security.Security.insertProviderAt(BCFIPS, 1)

  # Now retry DES — if SecurityHelper routes through its securityProvider,
  # and BCFIPS rejects DES, this will throw
  begin
    c = OpenSSL::Cipher.new("des-cbc")
    c.encrypt
    c.key = "12345678"
    c.iv  = "12345678"
    ct = c.update("hello world!") + c.final
    puts "  DES after BCFIPS inject: ACCEPTED (#{ct.bytesize} bytes)"
    puts "  VERDICT: jruby-openssl does NOT route through SecurityHelper's provider for this call"
  rescue java.lang.Error => e
    puts "  DES after BCFIPS inject: BLOCKED (Error) — #{e.class}: #{e.message.lines.first.chomp}"
    puts "  VERDICT: BCFIPS enforcement WORKS when SecurityHelper routes through it"
  rescue => e
    puts "  DES after BCFIPS inject: #{e.class}: #{e.message.lines.first.chomp}"
    puts "  VERDICT: blocked/errored after BCFIPS injection"
  end

  begin
    result = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("md5"), "key", "data")
    puts "  HMAC-MD5 after BCFIPS inject: ACCEPTED => #{result}"
    puts "  VERDICT: HMAC-MD5 does NOT go through SecurityHelper's provider"
  rescue java.lang.Error => e
    puts "  HMAC-MD5 after BCFIPS inject: BLOCKED (Error) — #{e.class}: #{e.message.lines.first.chomp}"
    puts "  VERDICT: BCFIPS enforcement WORKS for HMAC when SecurityHelper routes through it"
  rescue => e
    puts "  HMAC-MD5 after BCFIPS inject: #{e.class}: #{e.message.lines.first.chomp}"
  end

  # Restore
  field.set(nil, old_provider)
rescue => e
  puts "  Could not inject BCFIPS into SecurityHelper: #{e.class}: #{e.message}"
end
puts

# ──────────────────────────────────────────────────────────────────────────────
# TEST D: TLS path — what provider does SSLContext use?
# ──────────────────────────────────────────────────────────────────────────────
puts "=== TEST D: TLS/SSLContext provider routing ==="
begin
  ctx = OpenSSL::SSL::SSLContext.new
  puts "SSLContext created OK: #{ctx.class}"
  # Probe what JCE SSLContext provider is in use
  jssl = javax.net.ssl.SSLContext.getInstance("TLS")
  puts "JCE SSLContext provider: #{jssl.getProvider.getName}"
rescue => e
  puts "SSLContext: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

# ──────────────────────────────────────────────────────────────────────────────
# TEST E: Baseline — JCE DES directly through BCFIPS (should be blocked)
# ──────────────────────────────────────────────────────────────────────────────
puts "=== TEST E: Baseline JCE DES via explicit BCFIPS ==="
begin
  c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", BCFIPS)
  puts "RESULT: ACCEPTED — BCFIPS allowed DES (approved_only not active?)"
rescue java.lang.Error => e
  puts "RESULT: BLOCKED (Error) — #{e.class}: #{e.message.lines.first.chomp}"
rescue java.lang.Exception => e
  puts "RESULT: BLOCKED (Exception) — #{e.class}: #{e.message.lines.first.chomp}"
rescue => e
  puts "RESULT: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

puts "=== SUMMARY ==="
puts "If TEST A/B show ACCEPTED and TEST E shows BLOCKED:"
puts "  jruby-openssl does NOT route through BCFIPS for Cipher/HMAC regardless of flags"
puts "If TEST C shows BLOCKED after injection:"
puts "  jruby-openssl would be forceable IF the provider swap could be made permanent at init time"
puts "  The only way to do that reliably is to patch SecurityHelper or boot ordering"
