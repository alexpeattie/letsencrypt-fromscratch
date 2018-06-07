%w(openssl base64 json httparty dnsimple tempfile net/scp resolv uri).each { |lib| require lib }

HTTParty::Basement.default_options.update(debug_output: $stdout)

# Ruby EC key implementation monkey-patch (see https://alexpeattie.com/blog/signing-a-csr-with-ecdsa-in-ruby)
OpenSSL::PKey::EC.send(:alias_method, :private?, :private_key?)

DIRECTORY_URI = 'https://acme-staging-v02.api.letsencrypt.org/directory'.freeze

# domain = *.example.com for a wildcard certificate
domain, root_domain, email = 'le.example.com', 'example.com', 'me+bye@example.com'
preferred_challenge = 'http-01' # or 'dns-01',
certificate_type = 'rsa' # or ecdsa

def base64_le(data)
  txt_data = data.respond_to?(:entries) ? JSON.dump(data) : data
  Base64.urlsafe_encode64(txt_data).delete('=')
end

def client_key
  @client_key ||= begin
    client_key_path = File.expand_path('~/.ssh/id_rsa')
    OpenSSL::PKey::RSA.new IO.read(client_key_path)
  end
end

def jwk
  @jwk ||= {
    e: base64_le(client_key.e.to_s(2)),
    kty: 'RSA',
    n: base64_le(client_key.n.to_s(2))
  }
end

def hash_algo
  OpenSSL::Digest::SHA256.new
end

def nonce
  HTTParty.head(endpoints['newNonce'])['Replay-Nonce']
end

def endpoints
  @endpoints ||= HTTParty.get(DIRECTORY_URI).to_h
end

def protected_header(url, kid = nil)
  metadata = { alg: 'RS256', nonce: nonce, url: url }

  if kid
    metadata.merge!({ kid: kid })
  else
    metadata.merge!({ jwk: jwk })
  end

  return base64_le(metadata)
end

def signed_request(url, payload, kid = nil)
  request = {
    payload: base64_le(payload),
    protected: protected_header(url, kid)
  }
  request[:signature] = base64_le client_key.sign(hash_algo, [request[:protected], request[:payload]].join('.'))

  HTTParty.post(url, body: JSON.dump(request), headers: { 'Content-Type' => 'application/jose+json' })
end

def thumbprint
  key_digest = Digest::SHA256.digest(JSON.dump(jwk))
  base64_le(key_digest)
end

def upload(local_path, remote_path)
  server_ip = '162.243.201.152' # see Appendix 3
  Net::SCP.upload!(server_ip, 'root', local_path, remote_path)
end

tos_url = endpoints['meta']['termsOfService']
accept_tos = "N"
until accept_tos == "Y"
  puts "Do you accept the LetsEncrypt terms? (#{ tos_url })"
  accept_tos = gets.upcase.chars.first
end

new_registration = signed_request(endpoints['newAccount'], {
  termsOfServiceAgreed: true,
  contact: ['mailto:' + email]
})
kid = new_registration.headers['Location']

order = signed_request(endpoints['newOrder'], {
  identifiers: [{
    type: 'dns',
    value: domain
  }]
}, kid)

# challenges = order['authorizations'].flat_map do |auth_url|
#   HTTParty.get(auth_url)['challenges']
# end
# challenge, challenge_response = nil, nil

# http_challenge, dns_challenge = ['http-01', 'dns-01'].map do |challenge_type|
#   challenges.find { |challenge| challenge['type'] == challenge_type }
# end

# if preferred_challenge == 'http-01'
#   raise "Use the dns-01 for wildcard certs" if domain.start_with?("*")
#   challenge, challenge_response = http_challenge, [http_challenge['token'], thumbprint].join('.')
#   destination_dir = '/usr/share/nginx/html/.well-known/acme-challenge/'

#   IO.write('challenge.tmp', challenge_response)
#   upload('challenge.tmp', destination_dir + http_challenge['token'])
#   File.delete('challenge.tmp')
# end

# if preferred_challenge == 'dns-01'
#   record_name = ('_acme-challenge.' + domain.sub(root_domain, '')).sub(/[.*]+\Z/, '')
#   challenge, challenge_response = dns_challenge, [dns_challenge['token'], thumbprint].join('.')
#   record_contents = base64_le(hash_algo.digest challenge_response)

#   dnsimple = Dnsimple::Client.new(username: ENV['DNSIMPLE_USERNAME'], api_token: ENV['DNSIMPLE_TOKEN'])
#   challenge_record = dnsimple.domains.create_record(root_domain, record_type: 'TXT', name: record_name, content: record_contents, ttl: 60)

#   puts "Waiting for DNS record to propogate"
#   loop do
#     resolved_record = Resolv::DNS.open { |r| r.getresources("#{record_name}.#{root_domain}", Resolv::DNS::Resource::IN::TXT) }[0]
#     break if resolved_record && resolved_record.data == record_contents

#     sleep 5
#   end
# end

# signed_request(challenge['url'], {
#   keyAuthorization: challenge_response
# }, kid)

# loop do
#   challenge_result = HTTParty.get(challenge['url'])

#   case challenge_result['status']
#     when 'valid' then break
#     when 'pending' then sleep 2
#     else raise "Challenge attempt #{ challenge_result['status'] }: #{ challenge_result['error']['details'] }"
#   end
# end

# dnsimple.domains.delete_record(root_domain, challenge_record.id) if defined?(:challenge_record)

# domain_key = case certificate_type
#   when 'rsa' then OpenSSL::PKey::RSA.new(4096)
#   when 'ecdsa' then OpenSSL::PKey::EC.new('secp384r1').generate_key
#   else raise 'Unknown certificate type'
# end

# domain_filename = domain.gsub('.', '-')
# IO.write(domain_filename + '.key', domain_key.to_pem)

# csr = OpenSSL::X509::Request.new
# csr.public_key = case certificate_type
#   when 'rsa' then domain_key.public_key
#   when 'ecdsa' then OpenSSL::PKey::EC.new(domain_key)
# end
# alt_name = OpenSSL::X509::ExtensionFactory.new.create_extension("subjectAltName", "DNS: #{ domain }")
# extensions = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence([alt_name])])
# csr.add_attribute OpenSSL::X509::Attribute.new('extReq', extensions)

# csr.sign domain_key, hash_algo

# finalized_order = signed_request(order['finalize'], {
#   csr: base64_le(csr.to_der),
# }, kid)

# certificate = OpenSSL::X509::Certificate.new HTTParty.get(finalized_order['certificate']).body

# intermediate_cert_url = URI.join(DIRECTORY_URI, '../acme/issuer-cert')
# intermediate = OpenSSL::X509::Certificate.new HTTParty.get(intermediate_cert_url).body

# IO.write(domain_filename + '-cert.pem', certificate.to_pem)
# IO.write(domain_filename + '-chained.pem', [certificate.to_pem, intermediate].join("\n"))