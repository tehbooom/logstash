#!/usr/bin/env ruby
# Critical probe: if BCFIPS is inserted at position 1 BEFORE jruby-openssl loads,
# does the fallback Cipher.getInstance() / Mac.getInstance() pick BCFIPS first
# (and thus reject DES/MD5 under approved_only=true)?
#
# This is the "pre-register BCFIPS globally" approach — no SecurityHelper patching needed.
# SecurityHelper falls through to Cipher.getInstance(transformation) when securityProvider=nil.
# If BCFIPS is provider[0], that call hits BCFIPS first, which rejects DES.
#
# Run:
#   vendor/jruby/bin/jruby \
#     -J-Dorg.bouncycastle.fips.approved_only=true \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.1.jar:..." \
#     -J-Djruby.openssl.provider.register=false \
#     x-pack/qa/fips-pre-insert-bcfips-probe.rb

require "java"

java_import "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"
java_import "org.bouncycastle.crypto.CryptoServicesRegistrar"

BCFIPS = BouncyCastleFipsProvider.new

puts "approved_only active: #{CryptoServicesRegistrar.isInApprovedOnlyMode}"

# ── INSERT BCFIPS AT POSITION 1 BEFORE requiring openssl ──
java.security.Security.insertProviderAt(BCFIPS, 1)
puts "Providers BEFORE openssl load (BCFIPS pre-inserted): #{java.security.Security.getProviders.map(&:getName).join(', ')}"
puts

# Now load jruby-openssl — SecurityHelper will initialize
require "openssl"
puts "Providers AFTER openssl load: #{java.security.Security.getProviders.map(&:getName).join(', ')}"

# Check what SecurityHelper picked up
sh_class = java.lang.Class.forName(
  "org.jruby.ext.openssl.SecurityHelper",
  true,
  java.lang.Thread.currentThread.getContextClassLoader
)
sp_field = sh_class.getDeclaredField("securityProvider")
sp_field.setAccessible(true)
provider = sp_field.get(nil)
puts "SecurityHelper.securityProvider: #{provider.nil? ? 'nil (will use fallback Cipher.getInstance)' : "#{provider.getName}"}"
puts

# ──────────────────────────────────────────────────────────────────────────────
# THE KEY TEST: DES-CBC via jruby-openssl with BCFIPS pre-inserted at position 1
# If the fallback Cipher.getInstance("DES/CBC/PKCS5Padding") hits BCFIPS first,
# BCFIPS will reject DES and we'll get an error.
# ──────────────────────────────────────────────────────────────────────────────
puts "=== TEST: OpenSSL::Cipher.new('des-cbc') with BCFIPS pre-inserted ==="
begin
  c = OpenSSL::Cipher.new("des-cbc")
  c.encrypt
  c.key = "12345678"
  c.iv  = "12345678"
  ct = c.update("hello!!!!!!!!!!") + c.final
  puts "DES-CBC: ACCEPTED (#{ct.bytesize} bytes)"
  puts "VERDICT: BCFIPS pre-insertion DOES NOT force DES rejection"
  puts "  -> Cipher.getInstance fell through past BCFIPS to SunJCE"

  # Find out which provider it actually used
  f = sh_class.getDeclaredField("cipher") rescue nil
  if f
    f.setAccessible(true)
    backing = f.get(c.to_java) rescue nil
    puts "  Backing provider: #{backing&.getProvider&.getName rescue 'unknown'}"
  end
rescue java.lang.Error => e
  puts "DES-CBC: BLOCKED (java.lang.Error) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "VERDICT: BCFIPS pre-insertion FORCES DES rejection via the fallback path"
  puts "  -> Cipher.getInstance hit BCFIPS first and it threw"
rescue java.lang.Exception => e
  puts "DES-CBC: BLOCKED (Exception) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "VERDICT: BCFIPS pre-insertion causes DES to be rejected"
rescue OpenSSL::Cipher::CipherError => e
  puts "DES-CBC: CipherError — #{e.message.lines.first.chomp}"
  puts "VERDICT: blocked (exception propagated from BCFIPS through jruby-openssl)"
rescue => e
  puts "DES-CBC: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

puts "=== TEST: OpenSSL::HMAC.hexdigest(MD5) with BCFIPS pre-inserted ==="
begin
  r = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("md5"), "key", "data")
  puts "HMAC-MD5: ACCEPTED => #{r}"
  puts "VERDICT: BCFIPS pre-insertion DOES NOT force HMAC-MD5 rejection"
rescue java.lang.Error => e
  puts "HMAC-MD5: BLOCKED (java.lang.Error) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "VERDICT: BCFIPS pre-insertion FORCES HMAC-MD5 rejection"
rescue java.lang.Exception => e
  puts "HMAC-MD5: BLOCKED (Exception) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "VERDICT: BCFIPS pre-insertion causes HMAC-MD5 rejection"
rescue => e
  puts "HMAC-MD5: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

puts "=== TEST: JCE fallback DES without explicit provider (BCFIPS at pos 1) ==="
begin
  jce = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")
  puts "JCE DES (no provider): ACCEPTED — provider=#{jce.getProvider.getName}"
  puts "  -> BCFIPS was bypassed in the provider search"
rescue java.lang.Error => e
  puts "JCE DES (no provider): BLOCKED (Error) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "  -> BCFIPS at position 1 DID block it"
rescue java.lang.Exception => e
  puts "JCE DES (no provider): BLOCKED (Exception) — #{e.class}: #{e.message.lines.first.chomp}"
  puts "  -> BCFIPS at position 1 DID block it"
rescue => e
  puts "JCE DES (no provider): #{e.class}: #{e.message.lines.first.chomp}"
end
puts

puts "=== TEST: TLS with BCFIPS pre-inserted ==="
begin
  jssl = javax.net.ssl.SSLContext.getInstance("TLS")
  puts "JCE TLS provider: #{jssl.getProvider.getName}"
rescue => e
  puts "TLS: #{e.class}: #{e.message.lines.first.chomp}"
end
begin
  ctx = OpenSSL::SSL::SSLContext.new
  puts "OpenSSL::SSL::SSLContext: created OK"
rescue => e
  puts "OpenSSL::SSL::SSLContext: #{e.class}: #{e.message.lines.first.chomp}"
end
