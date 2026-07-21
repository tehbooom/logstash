#!/usr/bin/env ruby
# Probe: can SecurityHelper be redirected to BCFIPS?
# Tests three sub-mechanisms:
#   1. What does SecurityHelper pick up when non-FIPS BC is available (baseline)
#   2. After openssl loads, forcibly swap SecurityHelper.securityProvider to BCFIPS — do DES/MD5 throw?
#   3. What happens if we set SecurityHelper.securityProvider BEFORE openssl loads?
#
# Also probes the non-FIPS BC 1.84's DES behavior under approved_only=true
# (does it itself consult BCFIPS gate? No — it shouldn't, but let's verify)
#
# Run:
#   vendor/jruby/bin/jruby \
#     -J-Dorg.bouncycastle.fips.approved_only=true \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.1.jar:x-pack/build/fips-provider-jars/bctls-fips-2.0.22.jar:x-pack/build/fips-provider-jars/bcutil-fips-2.0.5.jar:x-pack/build/fips-provider-jars/bcpkix-fips-2.0.7.jar" \
#     -J-Djruby.openssl.provider.register=false \
#     x-pack/qa/fips-provider-swap-probe.rb

require "java"

java_import "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"
java_import "org.bouncycastle.crypto.CryptoServicesRegistrar"

BCFIPS = BouncyCastleFipsProvider.new
puts "approved_only active: #{CryptoServicesRegistrar.isInApprovedOnlyMode}"
puts

# ── Load openssl so SecurityHelper initializes (picks up non-FIPS BC 1.84) ──
require "openssl"
puts "Providers after openssl load: #{java.security.Security.getProviders.map { |p| "#{p.getName}(#{p.getClass.getSimpleName})" }.join(', ')}"
puts

# ── Introspect SecurityHelper ──
sh_class = java.lang.Class.forName(
  "org.jruby.ext.openssl.SecurityHelper",
  true,
  java.lang.Thread.currentThread.getContextClassLoader
)

sp_field = sh_class.getDeclaredField("securityProvider")
sp_field.setAccessible(true)
non_fips_bc = sp_field.get(nil)
puts "SecurityHelper.securityProvider before swap: #{non_fips_bc&.getName} (#{non_fips_bc&.getClass&.getName})"
puts "  non-FIPS BC version: #{non_fips_bc&.getVersionStr rescue 'N/A'}"
puts

# ── BASELINE: DES/MD5 with non-FIPS BC (as jruby-openssl uses it now) ──
puts "=== BASELINE (non-FIPS BC, current config) ==="
begin
  c = OpenSSL::Cipher.new("des-cbc")
  c.encrypt; c.key = "12345678"; c.iv = "12345678"
  ct = c.update("hello!!!!!!!!!!") + c.final
  puts "DES-CBC: ACCEPTED (#{ct.bytesize} bytes)"
rescue => e; puts "DES-CBC: #{e.class}: #{e.message.lines.first.chomp}"; end

begin
  r = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("md5"), "key", "data")
  puts "HMAC-MD5: ACCEPTED => #{r}"
rescue => e; puts "HMAC-MD5: #{e.class}: #{e.message.lines.first.chomp}"; end
puts

# ── SWAP: Replace SecurityHelper.securityProvider with BCFIPS ──
puts "=== AFTER SWAPPING SecurityHelper to BCFIPS ==="
java.security.Security.insertProviderAt(BCFIPS, 1)
sp_field.set(nil, BCFIPS)
puts "SecurityHelper.securityProvider now: #{sp_field.get(nil)&.getName}"

# Also need to clear the tryCipherInternal flag so it re-resolves
begin
  tci_field = sh_class.getDeclaredField("tryCipherInternal")
  tci_field.setAccessible(true)
  tci_field.set(nil, nil)
  puts "tryCipherInternal reset to nil"
rescue => e
  puts "Could not reset tryCipherInternal: #{e.message}"
end
puts

begin
  c = OpenSSL::Cipher.new("des-cbc")
  c.encrypt; c.key = "12345678"; c.iv = "12345678"
  ct = c.update("hello!!!!!!!!!!") + c.final
  puts "DES-CBC after swap: ACCEPTED (#{ct.bytesize} bytes) — NOT forced through BCFIPS"
rescue java.lang.Error => e
  puts "DES-CBC after swap: BLOCKED (java.lang.Error) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "  *** BCFIPS enforcement IS reachable via SecurityHelper swap ***"
rescue java.lang.Exception => e
  puts "DES-CBC after swap: BLOCKED (Exception) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "  *** BCFIPS enforcement IS reachable via SecurityHelper swap ***"
rescue OpenSSL::Cipher::CipherError => e
  puts "DES-CBC after swap: CipherError — #{e.message.lines.first.chomp}"
  puts "  *** Exception propagated through JRuby-OpenSSL ***"
rescue => e
  puts "DES-CBC after swap: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

begin
  r = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("md5"), "key", "data")
  puts "HMAC-MD5 after swap: ACCEPTED => #{r} — NOT forced through BCFIPS"
rescue java.lang.Error => e
  puts "HMAC-MD5 after swap: BLOCKED (java.lang.Error) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "  *** BCFIPS enforcement IS reachable via SecurityHelper swap ***"
rescue => e
  puts "HMAC-MD5 after swap: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

# ── Can SecurityHelper be pre-configured before openssl loads? ──
puts "=== WHAT setBouncyCastleProvider DOES (source analysis) ==="
puts "SecurityHelper loads BC via: Class.forName('org.bouncycastle.jce.provider.BouncyCastleProvider')"
puts "Is BouncyCastleProvider (non-FIPS) on classpath?"
begin
  klass = java.lang.Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
  puts "  YES — #{klass.getName}"
rescue java.lang.ClassNotFoundException
  puts "  NO — not on classpath (that's the goal when running FIPS-only)"
end
puts "Is BouncyCastleFipsProvider on classpath? YES (we loaded it above)"
puts
puts "Conclusion: when non-FIPS BC is absent from classpath, SecurityHelper.setBouncyCastleProvider()"
puts "returns nil, securityProvider stays nil, and SecurityHelper falls through to default JCE."
puts "There is no code path to load BCFIPS as the SecurityHelper provider."
