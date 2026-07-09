#!/usr/bin/env ruby
# Run from the repo root:
#
#   vendor/jruby/bin/jruby \
#     -J-cp "x-pack/build/fips-provider-jars/bc-fips-2.0.0.jar:x-pack/build/fips-provider-jars/bctls-fips-2.0.19.jar:x-pack/build/fips-provider-jars/bcutil-fips-2.0.3.jar:x-pack/build/fips-provider-jars/bcpkix-fips-2.0.7.jar" \
#     -J-Djruby.openssl.provider.register=false \
#     x-pack/qa/fips-hybrid-check.rb
#
# Proves whether BCFIPS in C:HYBRID mode enforces approved-only at the JCE level.
# If DES is accepted, algorithm guards in plugins are the sole enforcement layer.
# If DES is rejected, guards are defence-in-depth only.

require "java"

bcfips_class = java.lang.Class.forName("org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider")
bcfips = bcfips_class.newInstance
java.security.Security.insertProviderAt(bcfips, 1)

puts "Providers: #{java.security.Security.getProviders.map(&:getName).join(", ")}"
puts "BCFIPS first: #{java.security.Security.getProviders.first.getName == "BCFIPS"}"
puts

# Test 1: ask BCFIPS explicitly for DES
begin
  javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", bcfips)
  puts "BCFIPS explicit:  ACCEPTED DES/CBC  => approved_only NOT enforced at JCE level"
rescue => e
  puts "BCFIPS explicit:  REJECTED DES/CBC  => #{e.class}: #{e.message.lines.first.chomp}"
end

# Test 2: ask via JVM provider list (BCFIPS is first)
begin
  c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")
  puts "JVM provider list: ACCEPTED DES/CBC via #{c.getProvider.getName}  => same conclusion"
rescue => e
  puts "JVM provider list: REJECTED DES/CBC  => #{e.class}: #{e.message.lines.first.chomp}"
end

puts
puts "If both lines say ACCEPTED: plugin-level algorithm guards are the sole enforcement layer."
puts "If both lines say REJECTED: guards are defence-in-depth only."
