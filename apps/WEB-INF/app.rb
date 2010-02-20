require 'rubygems'
require 'sinatra'
require 'openssl'

get '/' do
  result = []

  result << "PKey test"
  result << do_pkey
  result << "BN test"
  result << do_bn
  result << "Digest test"
  result << do_digest
  result << "Cipher test"
  result << do_cipher
  result << "Random test"
  result << do_random
  result << "HMAC test"
  result << do_hmac

  result << "ASN.1 test"
  result << do_asn1
  result << "X.509::Certificate test"
  result << do_x509cert
  result << "PKCS#7 test"
  result << do_pkcs7

  result.map { |str|
    Rack::Utils.escape_html(str)
  }.join('<br/>')
end


def do_pkey
  protect do
    msg = 'Hello World'
    key = OpenSSL::PKey::RSA.new(512, 3)
    padding_mode = OpenSSL::PKey::RSA::PKCS1_PADDING
    cipher_text = key.private_encrypt(msg, padding_mode)
    plain_text = key.public_decrypt(cipher_text, padding_mode)
    "-> OK: #{plain_text} <-> #{base64(cipher_text)}"
  end
end

def do_bn
  protect do
    key = OpenSSL::PKey::RSA.new(512, 3)
    n = OpenSSL::BN.new(key.n.to_s)
    e = OpenSSL::BN.new(key.e.to_s)
    "-> OK: #{n}, #{e}"
  end
end

def do_digest
  protect do
    msg = 'Hello World'
    #digester = OpenSSL::Digest::Digest.new("MD5")
    digester = OpenSSL::Digest::MD5.new
    digester << msg
    digest = digester.hexdigest
    "-> OK: #{msg} -> #{digest}"
  end
end

def do_cipher
  protect do
    msg = 'Hello World'
    password = 'password'
    #cipher = OpenSSL::Cipher::Cipher.new('DES-EDE3-CBC')
    cipher = OpenSSL::Cipher::DES.new(:EDE3, "CBC")
    cipher.encrypt
    cipher.pkcs5_keyivgen(password)
    cipher_text = cipher.update(msg) + cipher.final
    cipher.decrypt
    cipher.pkcs5_keyivgen(password)
    plain_text = cipher.update(cipher_text) + cipher.final
    "-> OK: #{plain_text} <-> #{base64(cipher_text)}"
  end
end

def do_random
  protect do
    random = OpenSSL::Random.random_bytes(16)
    "-> OK: #{hex(random)}"
  end
end

def do_hmac
  protect do
    msg = 'Hello World'
    password = 'password'
    digester = OpenSSL::Digest::MD5.new
    hmac = OpenSSL::HMAC.hexdigest(digester, password, msg)
    "-> OK: #{msg} -> #{hmac}"
  end
end

def do_asn1
  protect do
    msg = "foo"
    v = OpenSSL::ASN1::OctetString.new(msg)
    "-> OK: #{msg} -> #{hex(v.to_der)}"
  end
end

def do_x509cert
  protect do
    cert = OpenSSL::X509::Certificate.new(CERT_PEM)
    "-> OK: #{cert.to_text}"
  end
end

def do_pkcs7
  protect do
    msg = "Hello World"
    password = "password"
    cert = OpenSSL::X509::Certificate.new(CERT_PEM)
    certs = [cert]
    cipher = OpenSSL::Cipher.new("des-ede3-cbc")
    cipher.encrypt
    cipher.pkcs5_keyivgen(password)
    p7 = OpenSSL::PKCS7.encrypt(certs, msg, cipher, OpenSSL::PKCS7::BINARY)
    "-> OK: #{msg} -> #{p7.data}"
  end
end

def protect(&block)
  begin
    yield
  rescue Exception => e
    dump_ex(e)
  end
end

def hex(bin)
  bin.unpack('H*')[0]
end

def base64(bin)
  [bin].pack('m*').gsub(/\n/, '').strip
end

def dump_ex(ex)
  "#{ex.message} (#{ex.class})\n" << (ex.backtrace || []).join("\n")
end

CERT_PEM = <<END
-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIBATANBgkqhkiG9w0BAQQFADA9MRMwEQYKCZImiZPyLGQB
GRYDb3JnMRkwFwYKCZImiZPyLGQBGRYJcnVieS1sYW5nMQswCQYDVQQDDAJDQTAe
Fw0wOTA1MjMxNTAzNDNaFw0wOTA1MjMxNjAzNDNaMD0xEzARBgoJkiaJk/IsZAEZ
FgNvcmcxGTAXBgoJkiaJk/IsZAEZFglydWJ5LWxhbmcxCzAJBgNVBAMMAkNBMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuV9ht9J7k4NBs38jOXvvTKY9
gW8nLICSno5EETR1cuF7i4pNs9I1QJGAFAX0BEO4KbzXmuOvfCpD3CU+Slp1enen
fzq/t/e/1IRW0wkJUJUFQign4CtrkJL+P07yx18UjyPlBXb81ApEmAB5mrJVSrWm
qbjs07JbuS4QQGGXLc+Su96DkYKmSNVjBiLxVVSpyZfAY3hD37d60uG+X8xdW5v6
8JkRFIhdGlb6JL8fllf/A/blNwdJOhVr9mESHhwGjwfSeTDPfd8ZLE027E5lyAVX
9KZYcU00mOX+fdxOSnGqS/8JDRh0EPHDL15RcJjV2J6vZjPb0rOYGDoMcH+94wID
AQABMA0GCSqGSIb3DQEBBAUAA4IBAQB8UTw1agA9wdXxHMUACduYu6oNL7pdF0dr
w7a4QPJyj62h4+Umxvp13q0PBw0E+mSjhXMcqUhDLjrmMcvvNGhuh5Sdjbe3GI/M
3lCC9OwYYIzzul7omvGC3JEIGfzzdNnPPCPKEWp5X9f0MKLMR79qOf+sjHTjN2BY
SY3YGsEFxyTXDdqrlaYaOtTAdi/C+g1WxR8fkPLefymVwIFwvyc9/bnp7iBn7Hcw
mbxtLPbtQ9mURT0GHewZRTGJ1aiTq9Ag3xXME2FPF04eFRd3mclOQZNXKQ+LDxYf
k0X5FeZvsWf4srFxoVxlcDdJtHh91ZRpDDJYGQlsUm9CPTnO+e4E
-----END CERTIFICATE-----
END
