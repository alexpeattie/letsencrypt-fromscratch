%w(openssl base64 json httparty dnsimple resolv stringio net/scp).each { |lib| require lib }

HTTParty::Basement.default_options.update(debug_output: $stdout)

DIRECTORY_URI = 'https://acme-v02.api.letsencrypt.org/directory'.freeze

# domain = *.example.com for a wildcard certificate
domain, root_domain, email = 'le.example.com', 'example.com', 'me@example.com'
preferred_challenge = 'http-01' # or 'dns-01',
certificate_type = 'rsa' # or ecdsa

def base64_le(data)
  txt_data = data.respond_to?(:entries) ? JSON.dump(data) : data
  Base64.urlsafe_encode64(txt_data).delete('=')
end

def client_key
  @client_key ||= begin
    client_key_path = File.expand_path('./ec-private.pem')
    OpenSSL::PKey::EC.new IO.read(client_key_path)
  end
end

def split_into_pieces(str, opts = {})
  str.chars.each_slice(opts[:piece_size]).map(&:join)
end

def jwk
  @jwk ||= begin
    pub_key_hex = client_key.public_key.to_bn.to_s(16)
    pub_key_octets = split_into_pieces(pub_key_hex, piece_size: 2)

    pub_key_octets.shift # drop the first octet (which just indicates key is uncompressed)
    coords_binary_data = pub_key_octets.map(&:hex).pack('c*')
    x, y = split_into_pieces(coords_binary_data, piece_size: coords_binary_data.length / 2)

    {
      crv: "P-#{ client_key.group.degree }",
      kty: 'EC',
      x: base64_le(x),
      y: base64_le(y)
    }
  end
end

def digest_size
  { 256 => 256, 384 => 384, 521 => 512 }[client_key.group.degree]
end

def hash_algo
  OpenSSL::Digest.const_get("SHA#{digest_size}").new
end

def nonce
  HTTParty.head(endpoints['newNonce'])['Replay-Nonce']
end

def endpoints
  @endpoints ||= HTTParty.get(DIRECTORY_URI).to_h
end

def protected_header(url, kid = nil)
  metadata = { alg: "ES#{ client_key.group.degree }", nonce: nonce, url: url }

  if kid
    metadata.merge!({ kid: kid })
  else
    metadata.merge!({ jwk: jwk })
  end

  return base64_le(metadata)
end

def signed_request(url, payload: '', kid: nil)
  request = {
    payload: base64_le(payload),
    protected: protected_header(url, kid)
  }
  signature = client_key.sign(hash_algo, [request[:protected], request[:payload]].join('.'))
  decoded_signature = OpenSSL::ASN1.decode(signature).to_a

  r, s = decoded_signature.map { |v| v.value.to_s(2) }

  request[:signature]  = base64_le(r + s)
  HTTParty.post(url, body: JSON.dump(request), headers: { 'Content-Type' => 'application/jose+json' })
end

def thumbprint
  key_digest = Digest::SHA256.digest(JSON.dump(jwk))
  base64_le(key_digest)
end

def upload(file_contents, remote_path)
  server_ip = '162.243.201.152' # see Appendix 3
  Net::SCP.upload!(server_ip, 'root', StringIO.new(file_contents), remote_path)
end

tos_url = endpoints['meta']['termsOfService']
accept_tos = "N"
until accept_tos == "Y"
  puts "Do you accept the LetsEncrypt terms? (#{ tos_url })"
  accept_tos = gets.upcase.chars.first
end

new_registration = signed_request(endpoints['newAccount'], payload: {
  termsOfServiceAgreed: true,
  contact: ['mailto:' + email]
})
kid = new_registration.headers['Location']

order = signed_request(endpoints['newOrder'], payload: {
  identifiers: [{
    type: 'dns',
    value: domain
  }]
}, kid: kid)

challenges = signed_request(order['authorizations'].first, kid: kid)['challenges']
challenge, challenge_response = nil, nil

http_challenge, dns_challenge = ['http-01', 'dns-01'].map do |challenge_type|
  challenges.find { |challenge| challenge['type'] == challenge_type }
end

if preferred_challenge == 'http-01'
  raise "Use the dns-01 for wildcard certs" if domain.start_with?("*")
  challenge, challenge_response = http_challenge, [http_challenge['token'], thumbprint].join('.')
  destination_dir = '/usr/share/nginx/html/.well-known/acme-challenge/'

  upload(challenge_response, destination_dir + http_challenge['token'])
end

if preferred_challenge == 'dns-01'
  record_name = ('_acme-challenge.' + domain.sub(root_domain, '')).sub(/[.*]+\Z/, '')
  challenge, challenge_response = dns_challenge, [dns_challenge['token'], thumbprint].join('.')
  record_contents = base64_le(hash_algo.digest challenge_response)

  dnsimple = Dnsimple::Client.new(access_token: ENV['DNSIMPLE_ACCESS_TOKEN'])
  account_id = dnsimple.identity.whoami.data.account.id

  challenge_record = dnsimple.zones.create_zone_record(account_id, root_domain, type: 'TXT', name: record_name, content: record_contents, ttl: 60)

  puts "Waiting for DNS record to propogate"
  loop do
    resolved_record = Resolv::DNS.open { |r| r.getresources("#{record_name}.#{root_domain}", Resolv::DNS::Resource::IN::TXT) }[0]
    break if resolved_record && resolved_record.data == record_contents

    sleep 5
  end
  dns_cleanup = Proc.new { dnsimple.zones.delete_zone_record(account_id, root_domain, challenge_record.data.id) }
end

signed_request(challenge['url'], payload: {}, kid: kid)

loop do
  challenge_result = signed_request(challenge['url'], kid: kid)

  case challenge_result['status']
    when 'valid' then break
    when 'pending' then sleep 2
    else raise "Challenge attempt #{ challenge_result['status'] }: #{ challenge_result['error']['details'] }"
  end
end

dns_cleanup.call if defined?(:dns_cleanup)

order = signed_request(order.headers['Location'], kid: kid)
raise("Unexpect order status (should be ready)") unless order['status'] == 'ready'

domain_key = case certificate_type
  when 'rsa' then OpenSSL::PKey::RSA.new(4096)
  when 'ecdsa' then OpenSSL::PKey::EC.new('secp384r1').generate_key
  else raise 'Unknown certificate type'
end

domain_filename = domain.gsub('.', '-').sub('*', 'wildcard')
IO.write(domain_filename + '.key', domain_key.to_pem)

csr = OpenSSL::X509::Request.new
csr.public_key = certificate_type == 'ecdsa' ? domain_key : domain_key.public_key

alt_name = OpenSSL::X509::ExtensionFactory.new.create_extension("subjectAltName", "DNS:#{ domain }")
extensions = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence([alt_name])])
csr.add_attribute OpenSSL::X509::Attribute.new('extReq', extensions)

csr.sign domain_key, hash_algo

finalized_order = signed_request(order['finalize'], payload: {
  csr: base64_le(csr.to_der),
}, kid: kid)

IO.write("#{ domain_filename }-cert.pem", signed_request(finalized_order['certificate'], kid: kid).body)