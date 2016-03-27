%w(openssl base64 json httparty dnsimple tempfile net/scp).each { |lib| require lib }

HTTParty::Basement.default_options.update(debug_output: $stdout)

# Ruby EC key implementation monkey-patch (see https://alexpeattie.com/blog/signing-a-csr-with-ecdsa-in-ruby)
OpenSSL::PKey::EC.send(:alias_method, :private?, :private_key?)

CA = 'https://acme-v01.api.letsencrypt.org'.freeze
domains = %w(le1.example.com le2.example.com)
root_domain, email = 'example.com', 'me@example.com'
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

def header
  @header ||= {
    alg: 'RS256',
    jwk: {
      e: base64_le(client_key.e.to_s(2)),
      kty: 'RSA',
      n: base64_le(client_key.n.to_s(2))
    }
  }
end

def hash_algo
  OpenSSL::Digest::SHA256.new
end

def nonce
  HTTParty.head(CA + '/directory')["Replay-Nonce"]
end

def signed_request(url, payload)
  request = {
    payload: base64_le(payload),
    header: header,
    protected: base64_le(header.merge(nonce: nonce))
  }
  request[:signature] = base64_le client_key.sign(hash_algo, [request[:protected], request[:payload]].join('.'))

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

signed_request(CA + '/acme/new-reg', {
  resource: 'new-reg',
  contact: ['mailto:' + email],
  agreement: 'https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf'
})

domains.each do |domain|
  auth = signed_request(CA + '/acme/new-authz', {
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
    record_name = "_acme-challenge." + domain.sub(root_domain, '').chomp('.')
    challenge, challenge_response = dns_challenge, [dns_challenge['token'], thumbprint].join('.')
    record_contents = base64_le(hash_algo.digest challenge_response)

    dnsimple = Dnsimple::Client.new(username: ENV['DNSIMPLE_USERNAME'], api_token: ENV['DNSIMPLE_TOKEN'])
    challenge_record = dnsimple.domains.create_record(root_domain, record_type: "TXT", name: record_name, content: record_contents)

    loop do
      resolved_record = Resolv::DNS.open { |r| r.getresources("#{record_name}.#{root_domain}", Resolv::DNS::Resource::IN::TXT) }[0]
      break if resolved_record && resolved_record.data == record_contents

      sleep 5
    end
  end

  signed_request(challenge['uri'], {
    resource: "challenge",
    keyAuthorization: challenge_response
  })

  loop do
    challenge_result = HTTParty.get(challenge['uri'], debug_output: $stdout)

    case challenge_result['status']
      when 'valid' then break
      when 'pending' then sleep 2
      else raise "Challenge attempt #{ challenge_result['status'] }: #{ challenge_result['error']['details'] }"
    end
  end

  dnsimple.domains.delete_record(root_domain, challenge_record.id) if defined?(:challenge_record)
end

domain_key = case certificate_type
  when 'rsa' then OpenSSL::PKey::RSA.new(4096)
  when 'ecdsa' then OpenSSL::PKey::EC.new('secp384r1').generate_key
  else raise "Unknown certificate type"
end

domain_filename = root_domain.gsub('.', '-')
IO.write(domain_filename + '.key', domain_key.to_pem)

csr = OpenSSL::X509::Request.new
csr.subject = OpenSSL::X509::Name.new([['CN', domains.first]])
csr.public_key = case certificate_type
  when 'rsa' then domain_key.public_key
  when 'ecdsa' then OpenSSL::PKey::EC.new(domain_key)
end
alt_names = domains.map { |domain| "DNS:#{domain}" }.join(", ")

extension = OpenSSL::X509::ExtensionFactory.new.create_extension("subjectAltName", alt_names, false)
csr.add_attribute OpenSSL::X509::Attribute.new(
  "extReq",
  OpenSSL::ASN1::Set.new(
    [OpenSSL::ASN1::Sequence.new([extension])]
  )
)
csr.sign domain_key, hash_algo

certificate_response = signed_request(CA + "/acme/new-cert", {
  resource: "new-cert",
  csr: base64_le(csr.to_der),
})

certificate = OpenSSL::X509::Certificate.new(certificate_response.body)
intermediate = HTTParty.get('https://letsencrypt.org/certs/lets-encrypt-x1-cross-signed.pem').body

IO.write(domain_filename + '-cert.pem', certificate.to_pem)
IO.write(domain_filename + '-chained.pem', [certificate.to_pem, intermediate].join("\n"))