#!/usr/bin/env ruby
# Deep probe: what Java class actually handles OpenSSL::Cipher operations?
# Use JVM security debug logging + reflection to trace the actual cipher implementation.
#
# Run:
#   vendor/jruby/bin/jruby \
#     -J-Dorg.bouncycastle.fips.approved_only=true \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.1.jar:..." \
#     -J-Djruby.openssl.provider.register=false \
#     x-pack/qa/fips-cipher-source-probe.rb

require "java"

java_import "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"
java_import "org.bouncycastle.crypto.CryptoServicesRegistrar"

BCFIPS = BouncyCastleFipsProvider.new
puts "approved_only active: #{CryptoServicesRegistrar.isInApprovedOnlyMode}"
puts

require "openssl"

# Reflectively get the underlying javax.crypto.Cipher from an OpenSSL::Cipher
puts "=== CIPHER IMPLEMENTATION PROBE ==="
c = OpenSSL::Cipher.new("des-cbc")

# The JRuby Ruby object wraps a Java CipherSuite — let's peel it
# OpenSSL::Cipher in jruby-openssl is org.jruby.ext.openssl.Cipher (Java class)
# It has a field `ciph` of type javax.crypto.Cipher
java_c = c.to_java  # Get the Java RubyObject
puts "Ruby cipher class: #{c.class}"
puts "Java object class: #{java_c.class.getName rescue 'N/A'}"

begin
  # Try to get the underlying Cipher object via reflection
  obj_class = java_c.getClass
  puts "Java cipher class hierarchy:"
  klass = obj_class
  while klass
    puts "  #{klass.getName}"
    klass = klass.getSuperclass
  end
  puts

  # Walk fields looking for javax.crypto.Cipher
  puts "Declared fields:"
  obj_class.getDeclaredFields.each do |f|
    puts "  #{f.getType.getName} #{f.getName}"
  end
rescue => e
  puts "Reflection failed: #{e.class}: #{e.message}"
end
puts

# Try via the Ruby method interface — see what object backs it
puts "=== FINDING BACKING CIPHER OBJECT ==="
begin
  # After encrypt+init, the cipher is initialized — find its provider
  c.encrypt
  c.key = "12345678"
  c.iv  = "12345678"

  # Navigate through Ruby object internals
  # In org.jruby.ext.openssl.Cipher, the cipher is held in 'ciph' field
  sh_class = java.lang.Class.forName(
    "org.jruby.ext.openssl.Cipher",
    true,
    java.lang.Thread.currentThread.getContextClassLoader
  )
  puts "Found Cipher class: #{sh_class.getName}"
  puts "Fields in org.jruby.ext.openssl.Cipher:"
  sh_class.getDeclaredFields.each do |f|
    f.setAccessible(true)
    val = begin; f.get(java_c); rescue; "N/A"; end
    puts "  #{f.getType.getName} #{f.getName} = #{val.class.getName rescue val.class} #{val.respond_to?(:getProvider) ? "provider=#{val.getProvider.getName rescue 'err'}" : ''}"
  end
rescue => e
  puts "Could not probe Cipher internals: #{e.class}: #{e.message}"
end
puts

# ── Probe whether the Cipher impl is from a specific provider ──
puts "=== WHICH PROVIDER BACKS DES-CBC? ==="
begin
  # Try getting the javax.crypto.Cipher through a direct JCE call
  # to see which provider gets selected with no explicit provider arg
  jce_cipher = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")
  puts "JCE DES/CBC provider (no explicit): #{jce_cipher.getProvider.getName}"
rescue java.lang.Exception => e
  puts "JCE DES/CBC (no explicit provider): BLOCKED — #{e.class}: #{e.message.lines.first.chomp}"
end

# Try via SunJCE specifically
begin
  sun_provider = java.security.Security.getProvider("SunJCE")
  jce_cipher = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", sun_provider)
  puts "JCE DES/CBC via SunJCE: ACCEPTED — provider: #{jce_cipher.getProvider.getName}"
rescue java.lang.Exception => e
  puts "JCE DES/CBC via SunJCE: BLOCKED — #{e.class}: #{e.message.lines.first.chomp}"
end

# Try via non-FIPS BC (should it be loaded)
begin
  bc_provider = java.security.Security.getProvider("BC")
  if bc_provider
    jce_cipher = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", bc_provider)
    puts "JCE DES/CBC via BC (non-FIPS): ACCEPTED — #{jce_cipher.getProvider.getName}"
  else
    puts "JCE BC (non-FIPS) provider: NOT in security provider list"
  end
rescue java.lang.Exception => e
  puts "JCE DES/CBC via BC: BLOCKED — #{e.class}: #{e.message.lines.first.chomp}"
rescue => e
  puts "JCE DES/CBC via BC: #{e.class}: #{e.message.lines.first.chomp}"
end
puts

# ── Key finding: what happens if we REMOVE SunJCE? ──
puts "=== WHAT IF WE REMOVE SUNJCE FROM PROVIDER LIST? ==="
begin
  java.security.Security.removeProvider("SunJCE")
  puts "SunJCE removed. Current providers: #{java.security.Security.getProviders.map(&:getName).join(', ')}"

  begin
    c2 = OpenSSL::Cipher.new("des-cbc")
    c2.encrypt; c2.key = "12345678"; c2.iv = "12345678"
    ct = c2.update("hello!!!!!!!!!!") + c2.final
    puts "DES-CBC without SunJCE: ACCEPTED (#{ct.bytesize} bytes) — uses some other provider"
  rescue OpenSSL::Cipher::CipherError => e
    puts "DES-CBC without SunJCE: CipherError — #{e.message}"
  rescue => e
    puts "DES-CBC without SunJCE: #{e.class}: #{e.message.lines.first.chomp}"
  end
rescue => e
  puts "Could not remove SunJCE: #{e.class}: #{e.message}"
end
puts

puts "=== ALL CURRENT PROVIDERS AND THEIR DES SERVICE ==="
java.security.Security.getProviders.each do |p|
  des_svc = p.getService("Cipher", "DES")
  puts "  #{p.getName}: DES=#{des_svc ? des_svc.getClassName : 'absent'}"
end
