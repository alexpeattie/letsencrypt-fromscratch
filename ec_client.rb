%w(openssl base64 json httparty dnsimple tempfile net/scp resolv nitlink/response).each { |lib| require lib }

HTTParty::Basement.default_options.update(debug_output: $stdout)

# Ruby EC key implementation monkey-patch (see https://alexpeattie.com/blog/signing-a-csr-with-ecdsa-in-ruby)
OpenSSL::PKey::EC.send(:alias_method, :private?, :private_key?)

DIRECTORY_URI = 'https://acme-v01.api.letsencrypt.org/directory'.freeze
domain, root_domain, email = 'le.example.com', 'example.com', 'me@example.com'
preferred_challenge = 'http-01' # or 'dns-01',
certificate_type = 'rsa' # or ecdsa

def base64_le(data)
  txt_data = data.respond_to?(:entries) ? JSON.dump(data) : data
  Base64.urlsafe_encode64(txt_data).delete('=')
end

def client_key
  @client_key ||= begin
    client_key_path = File.expand_path('~/Desktop/ec-private.pem')
    OpenSSL::PKey::EC.new IO.read(client_key_path)
  end
end

def split_into_pieces(str, opts = {})
  str.chars.each_slice(opts[:piece_size]).map(&:join)
end

def header
  @header ||= begin
    combined_coordinates = client_key.public_key.to_bn.to_s(16)
    coord_octets = split_into_pieces(combined_coordinates, piece_size: 2)

    coord_octets.shift # drop the first octet (which just indicates key is uncompressed)
    coords_bin = coord_octets.map(&:hex).pack('c*')
    x, y = split_into_pieces(coords_bin, piece_size: coords_bin.length / 2)

    {
      alg: "ES#{ client_key.group.degree }",
      jwk: {
        crv: "P-#{ client_key.group.degree }",
        x: base64_le(x),
        kty: 'EC',
        y: base64_le(y)
      }
    }
  end
end

def hash_algo
  bit_size = client_key.group.degree
  bit_size = 512 if bit_size == 521

  OpenSSL::Digest.const_get("SHA#{bit_size}").new
end

def nonce
  HTTParty.head(DIRECTORY_URI)['Replay-Nonce']
end

def endpoints
  @endpoints ||= HTTParty.get(DIRECTORY_URI).to_h
end

def signed_request(url, payload)
  request = {
    payload: base64_le(payload),
    header: header,
    protected: base64_le(header.merge(nonce: nonce))
  }
  signature = client_key.dsa_sign_asn1 hash_algo.digest([request[:protected], request[:payload]].join('.'))
  decoded_signature = OpenSSL::ASN1.decode(signature).to_a

  r, s = decoded_signature.map { |v| v.value.to_s(2) }

  request[:signature]  = base64_le(r + s)
  HTTParty.post(url, body: JSON.dump(request))
end

def thumbprint
  jwk = JSON.dump(header[:jwk])
  thumbprint = base64_le(Digest::SHA256.digest jwk)
end

def upload(local_path, remote_path)
  server_ip = '162.243.201.152' # see Appendix 3
  Net::SCP.upload!(server_ip, 'root', local_path, remote_path)
end

new_registration = signed_request(endpoints['new-reg'], {
  resource: 'new-reg',
  contact: ['mailto:' + email]
})

# accept Subscriber Agreement
if new_registration.code == 201
  signed_request(new_registration.headers['Location'], {
    resource: 'reg',
    agreement: new_registration.links.by_rel('terms-of-service').target
  })
end

auth = signed_request(endpoints['new-authz'], {
  resource: 'new-authz',
  identifier: {
    type: 'dns',
    value: domain
  }
})

challenge, challenge_response = nil, nil

http_challenge, dns_challenge = ['http-01', 'dns-01'].map do |challenge_type|
  auth['challenges'].find { |challenge| challenge['type'] == challenge_type }
end

if preferred_challenge == 'http-01'
  challenge, challenge_response = http_challenge, [http_challenge['token'], thumbprint].join('.')
  destination_dir = '/usr/share/nginx/html/.well-known/acme-challenge/'

  IO.write('challenge.tmp', challenge_response)
  upload('challenge.tmp', destination_dir + http_challenge['token'])
  File.delete('challenge.tmp')
end

if preferred_challenge == 'dns-01'
  record_name = ('_acme-challenge.' + domain.sub(root_domain, '')).chomp('.')
  challenge, challenge_response = dns_challenge, [dns_challenge['token'], thumbprint].join('.')
  record_contents = base64_le(hash_algo.digest challenge_response)

  dnsimple = Dnsimple::Client.new(username: ENV['DNSIMPLE_USERNAME'], api_token: ENV['DNSIMPLE_TOKEN'])
  challenge_record = dnsimple.domains.create_record(root_domain, record_type: 'TXT', name: record_name, content: record_contents, ttl: 60)

  loop do
    resolved_record = Resolv::DNS.open { |r| r.getresources("#{record_name}.#{root_domain}", Resolv::DNS::Resource::IN::TXT) }[0]
    break if resolved_record && resolved_record.data == record_contents

    sleep 5
  end
end

signed_request(challenge['uri'], {
  resource: 'challenge',
  keyAuthorization: challenge_response
})

loop do
  challenge_result = HTTParty.get(challenge['uri'])

  case challenge_result['status']
    when 'valid' then break
    when 'pending' then sleep 2
    else raise "Challenge attempt #{ challenge_result['status'] }: #{ challenge_result['error']['details'] }"
  end
end

dnsimple.domains.delete_record(root_domain, challenge_record.id) if defined?(:challenge_record)

domain_key = case certificate_type
  when 'rsa' then OpenSSL::PKey::RSA.new(4096)
  when 'ecdsa' then OpenSSL::PKey::EC.new('secp384r1').generate_key
  else raise 'Unknown certificate type'
end

domain_filename = domain.gsub('.', '-')
IO.write(domain_filename + '.key', domain_key.to_pem)

csr = OpenSSL::X509::Request.new
csr.subject = OpenSSL::X509::Name.new([['CN', domain]])
csr.public_key = case certificate_type
  when 'rsa' then domain_key.public_key
  when 'ecdsa' then OpenSSL::PKey::EC.new(domain_key)
end
csr.sign domain_key, hash_algo

certificate_response = signed_request(endpoints['new-cert'], {
  resource: 'new-cert',
  csr: base64_le(csr.to_der),
})
certificate = OpenSSL::X509::Certificate.new(certificate_response.body)
intermediate = OpenSSL::X509::Certificate.new HTTParty.get(certificate_response.links.by_rel('up').target).body

IO.write(domain_filename + '-cert.pem', certificate.to_pem)
IO.write(domain_filename + '-chained.pem', [certificate.to_pem, intermediate].join("\n"))