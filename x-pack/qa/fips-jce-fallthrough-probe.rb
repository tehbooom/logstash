#!/usr/bin/env ruby
# Probe: Why does Cipher.getInstance("DES/...") skip BCFIPS even when BCFIPS is at position 1?
# Answer: under approved_only=true, BCFIPS simply doesn't register DES in its service map,
# so JCE falls through to SunJCE which does have it.
# This probe confirms that AND tests what happens if we remove SunJCE entirely
# (the only remaining path to actually block DES in jruby-openssl).
#
# Run:
#   vendor/jruby/bin/jruby \
#     -J-Dorg.bouncycastle.fips.approved_only=true \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.1.jar:..." \
#     -J-Djruby.openssl.provider.register=false \
#     x-pack/qa/fips-jce-fallthrough-probe.rb

require "java"

java_import "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"
java_import "org.bouncycastle.crypto.CryptoServicesRegistrar"

BCFIPS = BouncyCastleFipsProvider.new
puts "approved_only active: #{CryptoServicesRegistrar.isInApprovedOnlyMode}"

# Insert BCFIPS before loading openssl
java.security.Security.insertProviderAt(BCFIPS, 1)
require "openssl"
puts

# ──────────────────────────────────────────────────────────────────────────────
# Why JCE skips BCFIPS for DES: service advertisement
# ──────────────────────────────────────────────────────────────────────────────
puts "=== BCFIPS SERVICE ADVERTISEMENT FOR DES/HMACMD5 ==="
des_svc = BCFIPS.getService("Cipher", "DES")
hmacmd5_svc = BCFIPS.getService("Mac", "HMACMD5")
puts "BCFIPS Cipher/DES service: #{des_svc.nil? ? 'NOT ADVERTISED (approved_only hides it)' : des_svc.getClassName}"
puts "BCFIPS Mac/HMACMD5 service: #{hmacmd5_svc.nil? ? 'NOT ADVERTISED' : hmacmd5_svc.getClassName}"

# Also try alternate names HMAC might use
%w[HMACMD5 HmacMD5 HmacMD5 HMAC-MD5].each do |name|
  svc = BCFIPS.getService("Mac", name)
  puts "BCFIPS Mac/#{name}: #{svc ? svc.getClassName : 'absent'}"
end
puts

# JCE behavior: when BCFIPS advertises nothing for "DES", JCE moves to the next provider
puts "=== JCE FALLTHROUGH BEHAVIOR ==="
puts "Provider order: #{java.security.Security.getProviders.map(&:getName).join(' -> ')}"
puts
puts "For DES/CBC/PKCS5Padding — which provider in the chain first has it?"
java.security.Security.getProviders.each do |p|
  svc = p.getService("Cipher", "DES")
  if svc
    puts "  FIRST MATCH: #{p.getName} — #{svc.getClassName}"
    break
  else
    puts "  #{p.getName}: no DES service (JCE skips)"
  end
end
puts

# ──────────────────────────────────────────────────────────────────────────────
# Remove SunJCE: the only remaining JCE provider with DES
# If SunJCE is absent, jruby-openssl's fallback Cipher.getInstance() fails
# and propagates OpenSSL::Cipher::CipherError — no DES available.
# ──────────────────────────────────────────────────────────────────────────────
puts "=== TEST: REMOVE SUNJCE — does DES fail? ==="
java.security.Security.removeProvider("SunJCE")
puts "SunJCE removed. Providers: #{java.security.Security.getProviders.map(&:getName).join(', ')}"
puts

begin
  c = OpenSSL::Cipher.new("des-cbc")
  c.encrypt; c.key = "12345678"; c.iv = "12345678"
  ct = c.update("hello!!!!!!!!!!") + c.final
  puts "DES-CBC without SunJCE: ACCEPTED (#{ct.bytesize} bytes)"
  puts "VERDICT: DES still works — some other provider has it"
rescue OpenSSL::Cipher::CipherError => e
  puts "DES-CBC without SunJCE: CipherError — #{e.message}"
  puts "VERDICT: DES rejected (no provider has it) — but this is 'no-such-algorithm', not BCFIPS enforcement"
rescue java.lang.Error => e
  puts "DES-CBC without SunJCE: BLOCKED (Error) — #{e.class}: #{e.message.lines.first.chomp}"
rescue => e
  puts "DES-CBC without SunJCE: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

begin
  r = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new("md5"), "key", "data")
  puts "HMAC-MD5 without SunJCE: ACCEPTED => #{r}"
  puts "VERDICT: HMAC-MD5 still works — some other provider has it"
rescue => e
  puts "HMAC-MD5 without SunJCE: #{e.class}: #{e.message.lines.first.chomp}"
  puts "VERDICT: HMAC-MD5 rejected without SunJCE"
end
puts

# ──────────────────────────────────────────────────────────────────────────────
# TLS: does jruby.openssl.ssl.provider=BCJSSE route TLS through BCFIPS?
# Test both the JCE SSLContext and what jruby-openssl's SSL layer uses
# ──────────────────────────────────────────────────────────────────────────────
puts "=== TLS ROUTING: jruby.openssl.ssl.provider property ==="
puts "ssl.provider property: #{java.lang.System.getProperty('jruby.openssl.ssl.provider').inspect}"
puts

# Check if BCJSSE is available
bcjsse_provider = java.security.Security.getProvider("BCJSSE")
puts "BCJSSE provider registered: #{bcjsse_provider.nil? ? 'NO' : bcjsse_provider.getName}"

# What SSLContext does jruby-openssl use?
# Look at the SSLContext Java class in OpenSSL::SSL
begin
  ssl_ctx_class = java.lang.Class.forName(
    "org.jruby.ext.openssl.SSL",
    true,
    java.lang.Thread.currentThread.getContextClassLoader
  )
  puts "Found SSL class: #{ssl_ctx_class.getName}"
rescue => e
  puts "Could not find SSL class: #{e.message}"
end

# Direct JCE SSLContext
begin
  ctx_default = javax.net.ssl.SSLContext.getInstance("TLS")
  puts "JCE SSLContext.getInstance('TLS'): provider=#{ctx_default.getProvider.getName}"
rescue => e
  puts "JCE SSLContext: #{e.class}: #{e.message}"
end

# Try BCJSSE
begin
  bctls = java.security.Security.getProvider("BCJSSE")
  if bctls
    ctx_bcjsse = javax.net.ssl.SSLContext.getInstance("TLS", bctls)
    puts "JCE SSLContext via BCJSSE: provider=#{ctx_bcjsse.getProvider.getName}"
  else
    puts "BCJSSE: not in provider list — bctls-fips jar not loaded or not registered"
  end
rescue => e
  puts "JCE SSLContext via BCJSSE: #{e.class}: #{e.message}"
end
