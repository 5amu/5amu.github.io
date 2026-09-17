#!/usr/bin/env ruby
# frozen_string_literal: true

# Encrypts a post's body in place with AES-256-GCM so it can only be read
# in-browser after entering the right password (e.g. an HTB flag). By default
# renders the body through the same kramdown/Rouge settings Jekyll uses, so
# the decrypted HTML matches every other post's styling exactly.
#
# Usage:
#   bundle exec ruby bin/encrypt-post.rb _posts/2026-01-01-htb-something.md
#   bundle exec ruby bin/encrypt-post.rb --html _posts/2026-01-01-htb-something.md
#   bundle exec ruby bin/encrypt-post.rb --prompt "Enter the flag found in DC04 to unlock the content" _posts/2026-01-01-htb-something.md
#
# --html: the body is already final HTML (e.g. converted from a Notion/other
# export) and is encrypted byte-for-byte, skipping the kramdown render step.
#
# --prompt: custom message shown above the flag input on the decrypt gate
# (e.g. a hint about which host/step the flag comes from), written to the
# post's `encrypted_prompt` front matter field (also editable directly, or
# via Pages CMS). Defaults to the generic "This post is encrypted. Enter the
# flag that unlocks it:".
#
# This OVERWRITES the post's body with ciphertext. Keep your own copy of the
# plaintext writeup (outside the repo, or in a gitignored folder) if you'll
# need to edit it later — there is no decrypt-in-place counterpart.

require "kramdown"
require "openssl"
require "base64"
require "securerandom"
require "io/console"
require "yaml"

KRAMDOWN_OPTIONS = {
  input: "GFM",
  auto_ids: true,
  entity_output: "as_char",
  smart_quotes: "lsquo,rsquo,ldquo,rdquo",
  hard_wrap: false,
  guess_lang: true,
  syntax_highlighter: "rouge",
}.freeze

PBKDF2_ITERATIONS = 250_000
KEY_LEN = 32 # AES-256

args = ARGV.dup
raw_html = args.delete("--html")
prompt = nil
if (idx = args.index("--prompt"))
  args.delete_at(idx)
  prompt = args.delete_at(idx)
end
path = args[0]
if path.nil? || !File.file?(path)
  warn "Usage: bundle exec ruby bin/encrypt-post.rb [--html] <path-to-post.md>"
  exit 1
end

raw = File.read(path)
_, front_matter, body = raw.split(/^---\s*$/, 3)
if front_matter.nil? || body.nil?
  warn "#{path} doesn't look like a post with YAML front matter."
  exit 1
end
front_matter = front_matter.strip

print "Flag (password) to encrypt this post with: "
password =
  begin
    $stdin.noecho(&:gets).to_s.chomp
  rescue Errno::ENOTTY, NotImplementedError
    $stdin.gets.to_s.chomp
  end
puts
if password.empty?
  warn "Refusing to encrypt with an empty password."
  exit 1
end

html = raw_html ? body.strip : Kramdown::Document.new(body, **KRAMDOWN_OPTIONS).to_html

salt = SecureRandom.random_bytes(16)
iv = SecureRandom.random_bytes(12)
key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, PBKDF2_ITERATIONS, KEY_LEN, OpenSSL::Digest.new("SHA256"))

cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
cipher.key = key
cipher.iv = iv
ciphertext = cipher.update(html) + cipher.final
sealed = ciphertext + cipher.auth_tag # Web Crypto expects the GCM tag appended to the ciphertext

encrypted_block = <<~HTML
  <div class="encrypted-post" data-salt="#{Base64.strict_encode64(salt)}" data-iv="#{Base64.strict_encode64(iv)}" data-ciphertext="#{Base64.strict_encode64(sealed)}" data-iterations="#{PBKDF2_ITERATIONS}">
    <noscript>This post is encrypted and requires JavaScript to decrypt.</noscript>
  </div>
HTML

unless front_matter =~ /^encrypted:\s*true\s*$/
  front_matter += "\nencrypted: true"
end

if prompt
  prompt_line = YAML.dump("encrypted_prompt" => prompt).sub(/\A---\n/, "").strip
  if front_matter =~ /^encrypted_prompt:.*$/
    front_matter.sub!(/^encrypted_prompt:.*$/, prompt_line)
  else
    front_matter += "\n#{prompt_line}"
  end
end

File.write(path, "---\n#{front_matter}\n---\n\n#{encrypted_block}")

puts "Encrypted #{path} in place."
puts "PBKDF2 iterations: #{PBKDF2_ITERATIONS}, key size: #{KEY_LEN * 8} bits."
