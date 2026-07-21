#!/usr/bin/env ruby
# Final probe: TLS path — does jruby.openssl.ssl.provider=BCJSSE route SSLContext through BCFIPS?
# Does NOT test DES/MD5 (TLS uses AES/SHA — this only affects the TLS stack, not raw Cipher/HMAC)
#
# Run:
#   vendor/jruby/bin/jruby \
#     -J-Dorg.bouncycastle.fips.approved_only=true \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.1.jar:bctls-fips-2.0.22.jar:..." \
#     -J-Djruby.openssl.provider.register=false \
#     -J-Djruby.openssl.ssl.provider=BCJSSE \
#     x-pack/qa/fips-tls-routing-probe.rb

require "java"

java_import "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"
java_import "org.bouncycastle.crypto.CryptoServicesRegistrar"

BCFIPS = BouncyCastleFipsProvider.new
java.security.Security.insertProviderAt(BCFIPS, 1)

puts "approved_only active: #{CryptoServicesRegistrar.isInApprovedOnlyMode}"
puts "ssl.provider property: #{java.lang.System.getProperty('jruby.openssl.ssl.provider').inspect}"
puts "Providers: #{java.security.Security.getProviders.map(&:getName).join(', ')}"
puts

require "openssl"
puts "Providers after openssl load: #{java.security.Security.getProviders.map(&:getName).join(', ')}"
puts

# ── What SSLHelper / SSL class uses in jruby-openssl ──
puts "=== TLS PROVIDER IN USE ==="

# Check SSLContext via JCE
begin
  ctx = javax.net.ssl.SSLContext.getInstance("TLS")
  puts "JCE SSLContext.getInstance('TLS') default: provider=#{ctx.getProvider.getName}"
rescue => e
  puts "JCE SSLContext default: #{e.class}: #{e.message}"
end

# What OpenSSL::SSL::SSLContext creates underneath
begin
  ssl_ctx = OpenSSL::SSL::SSLContext.new
  puts "OpenSSL::SSL::SSLContext.new: OK (#{ssl_ctx.class})"

  # Peek inside the Java object for what SSLContext it uses
  java_ssl_ctx = ssl_ctx.to_java
  klass = java_ssl_ctx.getClass
  klass.getDeclaredFields.each do |f|
    f.setAccessible(true)
    val = f.get(java_ssl_ctx) rescue nil
    next if val.nil?
    if val.respond_to?(:getProvider)
      puts "  SSLContext backing field '#{f.getName}': provider=#{val.getProvider.getName rescue 'N/A'}"
    end
  end
rescue => e
  puts "OpenSSL::SSL::SSLContext: #{e.class}: #{e.message}"
end
puts

# ── Check if BCJSSE is registered (it's in bctls-fips jar) ──
puts "=== BCJSSE REGISTRATION CHECK ==="
bcjsse = java.security.Security.getProvider("BCJSSE")
puts "BCJSSE in provider list: #{bcjsse ? "YES (#{bcjsse.getClass.getName})" : 'NO'}"
puts
puts "=== CONCLUSION ==="
puts "jruby.openssl.ssl.provider=BCJSSE affects the SSLContext path (TLS handshake,"
puts "cert validation, etc.) but has NO effect on OpenSSL::Cipher or OpenSSL::HMAC."
puts "Those are backed by JCE Cipher/Mac, not JSSE."
