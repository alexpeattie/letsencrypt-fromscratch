# Building a Let's Encrypt client from scratch

#### A step-by-step guide to building a LE/ACME client in <150 lines of code
<p align='center'><img src='https://letsencrypt.org/images/letsencrypt-logo-horizontal.svg'></p>

This is a (pretty detailed) how-to on building a simple ACME client from scratch, able to issue real certificates from [Let's Encrypt](https://letsencrypt.org). I've skipped things like error handling, object orientedness, tests - but not much tweaking would be needed for the client to be production-ready.

The code for the finished client is in [client.rb](https://github.com/alexpeattie/letsencrypt-fromscratch/blob/master/client.rb).

#### About the guide

This guide assumes no particular knowledge of TLS/SSL, cryptography or [ACME](https://github.com/letsencrypt/acme-spec/) - a general understanding of programming, HTTP and REST APIs is probably needed. It would also be useful to have a vague idea of what [Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography) is.

Hopefully this guide is useful to anyone looking to build a Let's Encrypt client, or anyone looking to understand more about how LE/ACME works. Following the guide, you should be able to create a fully fledged LE client and issue a valid certificate in less than an hour. The guide does assume **you control a domain name**.

Our specimen site is a static website powered by [nginx](http://nginx.org/), using [DNSimple](https://dnsimple.com/) as the DNS provider (see [Appendix 3: Our example site setup](#appendix-3-our-example-site-setup)). The mechanics of how we pass LE's challenges are based on this sample setup - but treat these just as illustrative examples.

The guide and client code are all [MIT licensed](https://github.com/alexpeattie/letsencrypt-fromscratch/blob/master/LICENSE.md).

#### Technology

This example code is written in Ruby (I used 2.3), and is largely dependency free (apart from OpenSSL). We use [HTTParty](https://github.com/jnunemaker/httparty) and [Nitlink](https://github.com/alexpeattie/nitlink) for more convenient API requests - but you could use vanilla `Net::HTTP` if you're a masochist :see_no_evil:. And we'll use additional gems to upload files and provision DNS records.

The choice of language is meant to be a background factor - the guide is (hopefully) illustrative & understandable even if you're not familiar with/interested in Ruby.

#### Credits

I heavily referenced Daniel Roesler's absolutely awesome [acme-tiny](https://github.com/diafygi/acme-tiny) and the [ACME spec](https://github.com/ietf-wg-acme/acme/) while writing this tutorial. I'd recommend checking out both as a supplement to this guide. Image credits at [the bottom](#image-credits).

## Table of Contents

  * [Loading our client key-pair](#1-loading-our-client-key-pair)
  * [Constructing a Let's Encrypt API request](#2-constructing-a-lets-encrypt-api-request)
    * [Base64 all the things](#a-base64-all-the-things)
    * [Payload](#b-payload)
    * [Header](#c-header)
    * [Protected header and the nonce](#d-protected-header-and-the-nonce)
    * [Signature](#e-signature)
    * [Making requests](#f-making-requests)
    * [Fetching the endpoints](#g-fetching-the-endpoints)
  * [Registering with Let's Encrypt](#3-registering-with-lets-encrypt)
    * [Responses](#responses)
  * [Passing the challenge](#4-passing-the-challenge)
    * [Asking Let's Encrypt for the challenges](#a-asking-lets-encrypt-for-the-challenges)
    * [Let's Encrypt gives us our challenges](#b-lets-encrypt-gives-us-our-challenges)
    * [Option 1: Completing the `http-01` challenge](#c-option-1-completing-the-http-01-challenge)
    * [Option 2: Completing the `dns-01` challenge](#d-option-2-completing-the-dns-01-challenge)
    * [Telling LE we've completed the challenge](#e-telling-le-weve-completed-the-challenge)
    * [Wait for LE to acknowledge the challenge has been passed](#f-wait-for-le-to-acknowledge-the-challenge-has-been-passed)
  * [Issuing the certificate :tada:](#5-issuing-the-certificate-tada)
    * [Formatting tweaks](#formatting-tweaks)
    * [Adding intermediates](#adding-intermediates)
  <hr>
  * [Appendix 1: Installing and testing the certificate](#appendix-1-installing-and-testing-the-certificate)
    * [Installation (with nginx)](#installation-with-nginx)
    * [Testing](#testing)
  * [Appendix 2: The trust chain & intermediate certificates](#appendix-2-the-trust-chain--intermediate-certificates)
    * [Missing certificate chain](#missing-certificate-chain)
    * [LE root certificate](#le-root-certificate)
  * [Appendix 3: Our example site setup](#appendix-3-our-example-site-setup)
  * [Appendix 4: Multiple subdomains](#appendix-4-multiple-subdomains)
  * [Appendix 5: Key size](#appendix-5-key-size)
    * [ECDSA keys](#ecdsa-keys)
  * [Appendix 6: IDN support](#appendix-6-idn-support)
  * [Further reading](#further-reading)
    * [TLS/SSL in general](#tlsssl-in-general)
    * [Let's Encrypt](#lets-encrypt)
  * [Image credits](#image-credits)
  * [Author](#author)
  * [Changelog](#changelog)

## 1. Loading our client key-pair

<p align="center"><img src="https://cloud.githubusercontent.com/assets/636814/20456560/d7c28f1a-ae70-11e6-9040-32df7534c00f.png" width='200'></p>

The process of generating our certificate heavily depends on have a **client key** - or, more accurately key-pair (comprising our public key and private key).

We'll **share our public key with Let's Encrypt** when we register, and sign all our requests with our private key - Let's Encrypt can use our public key to ensure our requests are genuinely from us (that they've been signed by our private key). We'll **never share our private key** with Let's Encrypt. We won't share it with any 3rd parties; although our web-server (nginx in our example app) will need access to it in order to encrypt the data it sends to clients.

It's fine to use existing SSH keys, if you've already got them generated and they're long enough:

```shell
openssl rsa -in ~/.ssh/id_rsa -text -noout | head -n 1
```

If you see or `Private-Key: (2048 bit)` or `Private-Key: (4096 bit)` you're good to go (if you're interested, there's more info about key size in [Appendix 5](#appendix-5-key-size)). Otherwise, we'll need to generate them - [Github has great instructions on how](https://help.github.com/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/). Let's begin by loading our key-pair into Ruby:

```ruby
require 'openssl'

client_key_path = File.expand_path('~/.ssh/id_rsa')
client_key = OpenSSL::PKey::RSA.new IO.read(client_key_path)
```

If our key is encrypted with a passphrase, we'll need to provide that as a 2nd argument:

```ruby
client_key = OpenSSL::PKey::RSA.new(IO.read(client_key_path), 'letmein')
```

<br>

## 2. Constructing a Let's Encrypt API request

The first, and probably hardest step, is constructing requests in the very particular format that Let's Encrypt demands. It's important to remember though, that in principle, the Let's Encrypt API is the same as any other API.

For example, using the [Github API](https://developer.github.com/v3/) I can programatically create an issue, by making a `POST` request to the target repo's `/issues` endpoint with a JSON payload that includes the issue title and body:

```json
POST https://api.github.com/repos/alexpeattie/letsencrypt-fromscratch/issues

{
  "title": "Bad examples",
  "body": "The code examples in the guide are hard to understand!"
}
```

The key difference with the Let's Encrypt API is we can't just send our JSON payload in a nice human-readable format as above, because we'll be signing it with our client private key to prove our identity. This is what a request to the Let's Encrypt API looks like:

```json
POST https://acme-v01.api.letsencrypt.org/acme/new-cert

{
  "payload": "eyJyZXNvdXJjZSI6Im5ldy1jZXJ0IiwiY3NyIjoiTUlJRVhEQ0NBa1FDQVFBd0Z6RVZNQk1HQTFVRUF3d01abWxzWlhNdWNHVm5MbU52TUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUE2ZG9JNWdlc1VWZVV2czJXN1h3LV9JcDg2eFl3ZnV0MDVNWE1aYWpWa3lMS1lhNHpjdGs3Y2hIN1ZuQWsxVF9uTXNaM0hYTlQ3X0J0R1hkYnlJR0FqRXhpR3F4cm5LejJqSS1JTVRNU1RKSklmRVhDUVJqUkx2U0c2S3VYbXk2aGhkS3BLMkpRam10OTh0QmxUY0NxbFFKNGRZWV9oMVFCTmYwZmUwN3p4T24zUXlaeU9Da05GMkdGQmZoSWZqTGRuVXJCbDBSejlTSUhLZkZTWW13SldKMTBBLWJiNVdRM2FkUWlNWF83amhYWHVBdUdDZnRBZ2h1UGdPWjlTalJXYVBpalNkOUxERWk1Y2pCalFsN1o4a0ZKTnV0VndSQlNFTDFIQVVNWE9ndkxKLW5mVjV4Tm15VHdmYTRsdXV4WEtsVnpJZFlmZDRUZWV1NHhwUTAxb29vQ0dLRUVCZ3VMQzdQLUtjemg4MUxXaTZtcExIRVZwOTNzWi1QZDZvNlROMFlabVZjaUwtNlJpTGRXY2hUeEtkbjNvTS1UYmRBTUVxb3VmTU5JYkh6LUVHREFxUkhGOUxCTU43bFlPcWJ0dWFmcjduN1EtVmQxN19KTGIxcnpONVFmclZvd2o4cUJpUHlRUndXbDhqN2hiLVpCR1NpMlJNb0V3LWNURG1KYjIweWUwQXZrWHhqVmxqbTN1aGpWVWRHTEtTQ0dfM1I4V0VuWEI3akRTV3Zpd0NEdDFKLWtPSW5EOEVUcjFvVDJKWWJ5N0FsaS12R25jdjJRdlhSb010RG9MN3F0MmkzSHNNZzhORjFDSHVhRUQ3RXdiTEMwRTRpWnZfcUw2WW45endqMVZ2bUZtbjA3T1ItanVOYkFnUXAtb01XR1lORDFKMnRpSW5QV0RtVUNBd0VBQWFBQU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQ0FRREdPdjUxc1hlUWNSLVhYMmUtbDZfSEt1WjNfVTdKbTJmNWtMMWJvbkpwOUM0UExacVNZMzNDZE5FbE1BcEVRczFzLTVhWEJCemRYWWE1X05hTFB2cm5fRm5mb2d1cnJHOXV6cU1vT0QtMjMtUnd5QkNLZFpNQ3gyVmd0YWNFU3RiZ2RLamNMRnRNRVE4YnR1NHIxMXVKQWlrblRIQnk4V3ZmaHREVS1Da0FkT2FYZV8zMktKSVV4Z05LSzhiYnRVUGlFc21jd3VqUGVzUkprWUh1QWVKc2JFQkY5ekVZNjlCazZiZVZKUUpxRjR4VjhYYmJheGZSX1N6TG5NWnJZNFhoNDNXbGRPN1UzZm9BZHYtLWk3eTlDbDUxaTJRV1RZMHFGcGVmd19nUU93SFFWMW9BRWJ0OWwyYkgyNGEtZ2NKUE9RNEhTdTBEV0ZHaFdSVkVuMUJsQ01XMkxGQnp2elpzMGdIaFhnQ1psVnNGcE1nYndJMThBLTA4UjZvS2FRWC1fM2tDb0FIaXcxQ1pdanaVQ1ZVOVRZNXNUMVlnZXBJVzBkT0VHYXY3YUJMXzNCbk9HVzVlMlZ2LXN5aGVSZS1ORzhXTEZiOHRyc2hMYTRPOVVjS3h3Nzl0MjFGaEhUYXhIblJLcDhFR3p3M2ZoZElMUW42YVlkb0k4Wm9faGJJaUE0cEhoMXlCbGpLU2Q3Zk1xTzkzX3JxV2Y4NzRfd2Q4N3RhcDFmb1pyZ1dYMVU5Wm9ZUnhFZ0FQOVN1cUdrcTJVUl9ucU9CQl9XaVBPM2ZGcFc3cTB6UEp1QUtBNWZIdDdFRG1HUldkTWNGXzM0SDdNenZPQk4tckI2S3VZTUtzWXpkS1ZEMDhwUnhUVVhKc3Nrb2t2MVF3aGNmNklzdEFtMDJ6bjhfWHBRIn0",
  "header": {
    "alg": "RS256",
    "jwk": {
      "e": "AQAB",
      "kty": "RSA",
      "n": "xVZG_h6B314tV_UNG-KUA_wldRuRjXvdcLwwtzOSBBjA1aGa-wabVUjazf2DrPWHlhiFlfom0sV0JgR2Ak5Ydlr4OOTqWCQ6m-ABnl71DvUs-u8eQwcLPsp-ccmRW3vYGuXoSP7-TEM9MSfAI-jeJ9vXeyDUGQDTD1FcBcZh886tR6LwyHBUbE0aD7I5I6pKr5kn24utnXcQ0LNoTOwjycexwzb-kGYHKfHdK5Chx1XLUkZIw7SYqePTchcBRsn6WOYLZ-orT4G58CRNbqpWa6qeRDijCOguUZfaJPuZLJl8ULIhtim0k1Y2e-X8tCNn-qacraicW6mPdlRcBUXAzQ"
    }
  },
  "protected": "eyJhbGciOiJSUzI1NiIsImp3ayI6eyJlIjoiQVFBQiIsImt0eTI6IlJTQSIsIm4iOiJ4VlpHX2g2QjMxNHRWX1VORy1LVUFfd2xkUnVSalh2ZGNMd3d0ek9TQkJqQTFhR2Etd2FiVlVqYXpmMkRyUFdIbGhpRmxmb20wc1YwSmdSMkFrNVlkbHI0T09UcVdDUTZtLTRMbmw3MUR2VXMtdThlUXdjTFBzcC1jY21SVzN2WUd1WG9TUDctVEVNOU1TZkFJLWplSjl2WGV5RFVHUURURDFGY0JjWmg4ODZ0UjZMd3lIQlViRTBhRDdJNUk2cEtyNWtuMjR1dG5YY1EwTE5vVE93anljZAv3emIta0dZSEtmSGRLNUNoeDFYTFVrWkl3N1NZcWVQVGNoY0JSc242V09ZTFotb3JUNEc1OENTTmJxcFdhNnFlUkRpakPNZ3VVWmZhSlB1WkxKbDhVTElodGltMGsxWTJlLVg4dENObi1xYWNyYWljVzZtUGRsUmNCVVhBelEifSwibm9uY2UiOiJidGY3SFpROHlvVERGNVphWjdaSnVGR05tOWR2cWhyNmdWVHR0NHZYbmFvIn0",
  "signature": "Mo1ZVEkT_QjsH4Yy98tTm3JEpsccnriVn5L18yjN2O1ea57V3apkDkkMb_3wleJ0YJskSuNrvtftJOC_-OqeT1_qbq4AjugEqMPle5I7VUAzshnh1DL7YiAgds5Fm06VtCuWUns5owF2MtVmjKMJHdHc9a_9-jilQsFWrTHEZgTt_ebBHazFpiEVcqoNCxhho-XxWZaHlvDOncJXUnqG0SWIa0OeM5Gm80jlPRlQoE5Wp6RqQvn1Fsb3NpzMUEQwD-s9JCvB4U2tQdpGLM5ynfbFwlgyS1AgKiQ4FLEftc55Yo9yOo0bXEugM7aDZS7-_TjqFD_N7r0IJHPp8fXrCQ"
}
```

This is what's called a JWS (JSON Web Signature), specifically a ["JWS Using Flattened JWS JSON Serialization"](https://tools.ietf.org/html/rfc7515#appendix-A.7) from [RFC 7515](https://tools.ietf.org/html/rfc7515). Scary stuff eh :ghost:? Don't worry, we'll break down the anatomy of this strange looking request in the sections below.

<br>

#### a. Base64 all the things

One problem we'll run into is that when we sign our payload with our key, we might not get ASCII out, even if we're only putting ASCII in. We can see this for ourselves:

```ruby
puts client_key.sign OpenSSL::Digest::SHA256.new, 'Hello world'
��ۉ��7�xM��\�AU=�KGQ��ao�:Q-H�WW�a_Ԇ����+a
                                          ��|X]�s}V�oya���'68L6����P����f��yKV���
�I@���a��[�����C���VXM+�
                        ��oQ�@�B�"]Uzr�N�R]]{9;�N:��G�ӗaM�S��H�ŵq���Bq�9��  ��So�Q���tk�;����z��d�<=�� +B
_t�
   �����~���<˯ޤ
                �%Ê�k��
```

To avoid dealing with non-ASCII characters we'll need to [Base64 encode](https://en.wikipedia.org/wiki/Base64) most of our data. The good news is Ruby comes with Base64 handling as [part of the standard library](http://ruby-doc.org/stdlib-2.3.0/libdoc/base64/rdoc/Base64.html):

```ruby
Base64.urlsafe_encode64('test')
 #=> "dGVzdA=="
```

There is a small tweak we'll need to make to keep Let's Encrypt happy - removing the padding characters (`=`) from our encoded data:

```ruby
Base64.urlsafe_encode64('test').delete('=')
 #=> "dGVzdA"
```

(Or in [Ruby 2.3](http://ruby-doc.org/stdlib-2.3.0/libdoc/base64/rdoc/Base64.html#method-i-urlsafe_encode64))

```ruby
Base64.urlsafe_encode64('test', padding: false)
```

Let's wrap that in a helper method - we'll be using it a lot as we build our request:

```ruby
def base64_le(data)
  Base64.urlsafe_encode64(data).delete('=')
end
```

<br>

#### b. Payload

The **payload** is the simplest part of our request. It's just JSON that we'll Base64 encode using our method above:

```ruby
base64_le '{"resource":"new-reg"}'
 #=> "eyJyZXNvdXJjZSI6ICJuZXctcmVnIn0"
 ```

This a totally valid payload that we can send to Let's Encrypt. Obviously it'll be more convienient not to have to construct JSON strings by hand - so let's load in the [JSON library](http://ruby-doc.org/stdlib-2.3.0/libdoc/json/rdoc/JSON.html) (again part of the Ruby standard lib):

```ruby
require 'json'

base64_le JSON.dump(resource: 'new-reg')
 #=> "eyJyZXNvdXJjZSI6ICJuZXctcmVnIn0"
```

For further convenience, we can make our Base64 helper method smarter. If the data we pass in is an array or hash, it should JSONify the data before encoding it:

```ruby
def base64_le(data)
  txt_data = data.respond_to?(:entries) ? JSON.dump(data) : data
  Base64.urlsafe_encode64(txt_data).delete('=')
end
```

That's all we need for our payload :smile:! As well as providing information about the request we want to make, it will form one half of the data we'll be signing.

<br>

#### c. Header

We'll need to give Let's Encrypt two things for it to validate the authenticity of the request: our public key, and the cryptographic hashing algorithm we're using to generate the signature. This info will go in our **header**.

The static parts of our header are as follows:

```ruby
header = {
  alg: 'RS256',
  jwk: {
    kty: 'RSA',
  }
}
```

`alg` corresponds with the hashing algorithm we want to use - in this case SHA-256 (or more technically [RSA PKCS#1 v1.5 signature with SHA-256](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-14#section-3.1), but we don't really have to worry about that here). `kty` means key type - our keys are RSA keys. `jwk` stands for JSON web key - a standard for sharing keys via JSON.

The parts of the key we're interested in are the public key exponent (e) and the modulus (n). Helpfully our `client_key` has corresponding methods (`client_key.e` and `client_key.n`) - the only additionally steps we need to take are converting them to binary strings with `to_s(2)` ([documented here](http://ruby-doc.org/stdlib-2.3.0/libdoc/openssl/rdoc/OpenSSL/BN.html#to_s-method)), then (you guessed it), Base64 encoding them. Let's also create a `header` convenience method:

```ruby
def header
  {
    alg: 'RS256',
    jwk: {
      e: base64_le(client_key.e.to_s(2)),
      kty: 'RSA',
      n: base64_le(client_key.n.to_s(2)),
    }
  }
end
```

<br>

#### d. Protected header and the nonce

We have our plaintext header - which contains the required components of our public key. We'll also need a **protected header** - basically a Base64 encoded version of our header which will form the other half of the data we'll be signing (alongside our payload).

The protected header contains one additional element which our unprotected header doesn't - a [cryptographic nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce). The linked article goes into lots of details, but a nonce is basically a one-time use code which we must attach to our request. It means if an attacker somehow sniffs out a request we made, and makes a carbon-copy duplicate request, the attackers attempt will fail (because the nonce has already been used).

<p align='center'><img src='http://media.tumblr.com/tumblr_m7hl1rtHfv1qc4uvwo1_500.gif' width='350'></p>

Let's Encrypt provides us a nonce in the headers of every response it gives us - so getting a nonce is just a case of requesting any Let's Encrypt API endpoint, and grabbing it from the `Replay-Nonce` header.

Ruby comes with the `Net::HTTP` library built in for making HTTP requests, but it's a bit cumbersome. To make our life easier, we'll use [HTTParty](https://github.com/jnunemaker/httparty) - although this is by no means a necessity.

```shell
gem install httparty
```

```ruby
require 'httparty'
```

(Note: you can also grab the [`Gemfile`](./Gemfile) provided in this repository, and `bundle install` to save yourself some typing.)

We'll send HTTParty's debug output to `$stdout` so we can see easily see the requests/responses happening:

```ruby
HTTParty::Basement.default_options.update(debug_output: $stdout)
```

As mentioned above, any Let's Encrypt API endpoint will do - let's use the `/directory` endpoint (effectively the root of the API). Because we only need the headers, we can just make a `HEAD` request:

```ruby
nonce = HTTParty.head('https://acme-v01.api.letsencrypt.org/directory')['Replay-Nonce']
```

We can now create our protected header:

```ruby
protected = base64_le(header.merge(nonce: nonce))
```

<br>

#### e. Signature

The last step to construct our request is proving its authenticity with a **signature**, generated using our *client private key*. First, let's consolidate everything we have so far:

```ruby
require 'openssl'
require 'base64'
require 'json'
require 'httparty'

def base64_le(data)
  txt_data = data.respond_to?(:entries) ? JSON.dump(data) : data
  Base64.urlsafe_encode64(txt_data).delete('=')
end

client_key_path = File.expand_path('~/.ssh/id_rsa')
client_key = OpenSSL::PKey::RSA.new IO.read(client_key_path)

payload = { some: 'data'}

header = {
  alg: 'RS256',
  jwk: {
    e: base64_le(client_key.e.to_s(2)),
    kty: 'RSA',
    n: base64_le(client_key.n.to_s(2)),
  }
}

nonce = HTTParty.head('https://acme-v01.api.letsencrypt.org/directory')['Replay-Nonce']

request = {
  payload: base64_le(payload),
  header: header,
  protected: base64_le(header.merge(nonce: nonce))
}
```

As mentioned [above](#c-header), we'll be using the SHA-256 hash function for our signing:

```ruby
hash_algo = OpenSSL::Digest::SHA256.new
```

The specific data we'll need to sign is our protected header and our payload, joined with a period:

```ruby
request[:signature] = client_key.sign(hash_algo, [ request[:protected], request[:payload] ].join('.'))
```

<br>

#### f. Making requests

Now we've built the request data just as Let's Encrypt wants, we have everything we need to start making requests:

```ruby
HTTParty.post(some_api_endpoint, body: JSON.dump(request))
```

Let's put everything into a reusable method that can take an arbitrary URL and payload. (We'll move `client_key`, `hash_algo`, `header` and `nonce` into methods at the same time):

```ruby
HTTParty::Basement.default_options.update(debug_output: $stdout)

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
  HTTParty.head('https://acme-v01.api.letsencrypt.org/directory')['Replay-Nonce']
end

def signed_request(url, payload)
  request = {
    payload: base64_le(payload),
    header: header,
    protected: base64_le(header.merge(nonce: nonce))
  }
  request[:signature] = client_key.sign(hash_algo, [ request[:protected], request[:payload] ].join('.'))

  HTTParty.post(url, body: JSON.dump(request))
end
```
<br>

#### g. Fetching the endpoints

The `/directory` endpoint that we use to fetch our nonce serves another purpose: it lists all the other endpoints which act as the starting points for all the core actions (registering a user, authorizing a domain, issuing a certificate etc.):

```json
{
  "key-change": "https://acme-staging.api.letsencrypt.org/acme/key-change",
  "new-authz": "https://acme-staging.api.letsencrypt.org/acme/new-authz",
  "new-cert": "https://acme-staging.api.letsencrypt.org/acme/new-cert",
  "new-reg": "https://acme-staging.api.letsencrypt.org/acme/new-reg",
  "revoke-cert": "https://acme-staging.api.letsencrypt.org/acme/revoke-cert"
}
```

(Note: unlike the API's endpoints, the directory is viewable without any kind of signing, you can just visit it [in your browser](https://acme-staging.api.letsencrypt.org/directory)).

Here the keys in the JSON object indicate the resource type, and the values are the URI we'll need to make a signed request to. Even though [Cool URIs don't change](https://www.w3.org/Provider/Style/URI), using the directory means we don't have to hard-code the endpoints - and so our client is more resilient to any changes Let's Encrypt might make (credit to [@kelunik](https://github.com/kelunik) for suggesting this).

To avoid making repeated requests to the directory, let's make an `endpoints` method:

```ruby
def endpoints
  @endpoints ||= HTTParty.get('https://acme-v01.api.letsencrypt.org/directory').to_h
end
```

Since we're referencing the directory endpoint in both our `endpoints` and `nonce` methods, we can dry up our code by moving it into a constant. This will also make it easier to, for example, switch to LE's [staging server](https://acme-staging.api.letsencrypt.org/).

```ruby
DIRECTORY_URI = 'https://acme-v01.api.letsencrypt.org/directory'.freeze

def nonce
  HTTParty.head(DIRECTORY_URI)['Replay-Nonce']
end

def endpoints
  @endpoints ||= HTTParty.get(DIRECTORY_URI).to_h
end
```

The neat thing is that this `DIRECTORY_URI` is the only URI we need to hardcode, every other endpoint we can either pull from the directory, or from the `Location` or `Link` headers of the API's responses. `Location` is easy to work with (it's just a single URI) - but `Link` headers need to be parsed. I've written a gem ([Nitlink](https://github.com/alexpeattie/nitlink)) for just that - so let's install and load it:

```shell
gem install nitlink
```

```ruby
require 'nitlink/response'
```

<br>

## 3. Registering with Let's Encrypt

OK, we've laid the foundations - let's make our first actual request to the Let's Encrypt API! The first step is to register our client public key with Let's Encrypt.

Since we're sending the public key with every request (in the `header` property of our JSON), we don't need to include much in the actual registration payload. At a minimum, we'll just need to specify the resource type: `new-reg` in this case.

```ruby
new_registration = signed_request(endpoints['new-reg'], {
  resource: 'new-reg',
})
```

We can optionally provide contact details (highly recommended), this will allow us to recover our key in case we lose it. We'll need to include the protocols for the contact details we provide - e.g. `mailto:` for email addresses, <strike>`tel:` for phone numbers</strike> (it turns out Let's Encrypt doesn't currently support this, see [here](https://github.com/letsencrypt/boulder/blob/release/docs/acme-divergences.md#section-62)).

```ruby
new_registration = signed_request(endpoints['new-reg'], {
  resource: 'new-reg',
  contact: ['mailto:me@alexpeattie.com']
})
```

<br>

#### Responses

Sending the request should give us back a successful response:

```json
-> "HTTP/1.1 201 Created"
-> "Content-Type: application/json"
-> "Location: https://acme-v01.api.letsencrypt.org/acme/reg/12345"
-> "Link: <https://acme-v01.api.letsencrypt.org/acme/new-authz>;rel=\"next\", <https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf>;rel=\"terms-of-service\""
...
{
  "id": 12345,
  "key": {
    "kty": "RSA",
    "n": "wlpAF2eAhpzJDGCco-c9hhd31NGAyhkFeivqfmt7ZQiphRiuSwF_0_3lOnCRpdpRIeVheIPVK6FofcFVmRjzdyDeZmN5ssk5oi2v1y8hSB7SM2QCoqlZ3L8uEGKzzwQfzSIQGIR56X5GrTKaCjBrzqrSM0VzRg5-gp8ZDqsyceSUaf7SgScxexfgbcaRXtJ1aVLYT5FfsDgV768gRcBxaKQapFQ47M7JN8OTOq6QIla6acp24eNo6PMtH8Mf0hJwpcWOs2A_0VcNzV7XBl8shYEeERyqbNXIZsF7njF8WInk7-v0EiYPV2w0xjBuFnbX7cw8YqveG81yirYGScR5ASeER5dxtWNyXFXkK9KpI13Vvf-0ivzrgeJTUsKz7EAjL2vof2QleKZHjP6f63rvaIMK5FaGojhHSzzMdeP3FaG1mP7N5vY3J0oZzhny_Jd9vNysCiklsUNUr8ZT-ocTKHbiO6ZEZdj8Wtjmpr5kvfPUtosNodaMUNFv-7UFRWNf49qJKo21UzpeeM7Us0hKPNVd9VU0qD0jsya7w1EjimiBqwo6vD_KoH-R2bwWlaQ9Ucy6ahfNPogI3zqMTpUfMXGA0uMj6anp-daOSwuEus2ogY0x12OUn3XivB9VzbCNadAT9JqKRrhRHE-7tfN6TFt7CtLjGCe1ShMn3wsMFBU",
    "e": "AQAB"
  },
  "contact": ["mailto:me@alexpeattie.com"],
  "initialIp": "101.222.66.199",
  "createdAt": "2015-12-12T12:07:23.755314388Z"
}
```

The successful response basically just echoes back to us our registration details. We can see the exponent + modulus (`e` and `n`) values of our public key included at the top, as well as the unique `id` of our new account.

Note that LE verifies the domains of emails we provide (by checking their DNS `A` record), so make sure it's a real domain, otherwise you'll get an 400 (Bad Request) response:

```json
{
  "type": "urn:acme:error:malformed",
  "detail": "Error creating new registration :: Validation of contact mailto:alex@artichokesandarmadillos.com failed: Server failure at resolver",
  "status": 400
}
```

If we try and register the same key again we'll get a 409 (Conflict) response:

```json
-> "HTTP/1.1 409 Conflict"
-> "Content-Type: application/problem+json"
-> "Location: https://acme-v01.api.letsencrypt.org/acme/reg/12345"
...
-> "Connection: close"
{
  "type": "urn:acme:error:malformed",
  "detail": "Registration key is already in use",
  "status": 409
}
```

Don't worry, there are no side effects to attempting to re-register the same client key multiple times :relaxed:.

#### Accepting the ToS

Although we've successfully registered, Let's Encrypt won't let us do anything useful (like issue a certificate), until we accept their [Subscriber Agreement](https://letsencrypt.org/repository/#lets-encrypt-subscriber-agreement).

To indicate our acceptance, we just need to make a request to the URI of our newly created user (returned in the response's `Location` header, in this case `https://acme-v01.api.letsencrypt.org/acme/reg/12345`) with the payload's `agreement` key set to the URI of the terms we're accepting. How do we know the URI of the terms? Eagle-eyed readers might have spotted above that it's returned as one of the response's `Link` headers:

```
Link: ... <https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf>;rel="terms-of-service"
```

We should also check that we got a 201 status (not a Conflict or malformed registration). Our final code for accepting the terms programatically looks like this:

```ruby
if new_registration.status == 201
  signed_request(new_registration.headers['Location'], {
    resource: 'reg',
    agreement: new_registration.links.by_rel('terms-of-service').target
  })
end
```

(The `.links` method depends on the [Nitlink](https://github.com/alexpeattie/nitlink) gem, we'll get a `NoMethodError` if it's not installed). Notice that the resource type has changed, since we're not creating a new user, but modifying an existing one. Also, a real client should probably prompt the user to actually read the agreement - rather than just auto-accepting it :innocent:!

<br>

## 4. Passing the challenge

<p align='center'><img src='http://ericdye.it/wp-content/uploads/2015/03/Challenge-Accepted-Meme.jpg' width='400'></p>

The next step is to inform Let's Encrypt which domain or subdomain we to provision a certificate for. In this guide I'm using the example **le.alexpeattie.com**. This is the first part of a multistep verification process to prove we're the legitimate owner of the domain:

  - [a).](#a-asking-lets-encrypt-for-the-challenges) We ask LE for the challenge
  - [b).](#b-lets-encrypt-gives-us-our-challenges) LE gives us a challenge to prove we control the domain
  - [c)](#c-option-1-completing-the-http-01-challenge) or [d).](#d-option-2-completing-the-dns-01-challenge) We complete the HTTP- or DNS-based challenge, and notify LE that we're ready
  - [e).](#e-telling-le-weve-completed-the-challenge) LE checks the challenge has been completed to it's satisfaction
  - [f).](#f-wait-for-le-to-acknowledge-the-challenge-has-been-passed) We verify that LE is happy the challenge has been passed :trophy:

<br>

Challenges are how we prove a sufficient level of control over the identifier (domain name) in question. We can do this either by serving a specific response when LE hits a specific URL (which generally means uploading a file to our web-server), provisioning a DNS record, or by leveraging the [Server Name Indication](https://tools.ietf.org/html/rfc6066#section-3) extension of TLS to serve a special self-signed certificate.

We'll cover the first two kinds of challenge: `http-01` and `dns-01` but not the third (`tls-sni-01`).

<br>

#### a. Asking Let's Encrypt for the challenges

Asking LE for our new challenge is just a case of making another request to the LE API - this time to create a `new-authz` (`authz` is short for **auth**ori**z**ation). 

As you can probably guess, this means making a request to the `new-authz` endpoint with our `resource` option set to (you guessed it) `new-authz`. Beyond that just need tell LE what identifier (domain name) we want to authorize:

```ruby
auth = signed_request(endpoints['new-authz'], {
  resource: 'new-authz',
  identifier: {
    type: 'dns',
    value: 'le.alexpeattie.com'
  }
})
```

The ACME spec is designed to be flexible enough to authorize more than just domain names in the future - which is why we have to explicitly state we're authorizing a domain name with `type: 'dns'`. We could authorize the root domain with `value: 'alexpeattie.com'`. We can also provide a Punycode encoded IDN, see [Appendix 6](#appendix-6-idn-support).

<br>

#### b. Let's Encrypt gives us our challenges

Let's Encrypt should send up back a nice meaty response like the below :meat_on_bone: -

```json
{
  "identifier": {
    "type": "dns",
    "value": "le.alexpeattie.com"
  },
  "status": "pending",
  "expires": "2016-01-15T19:28:33.644298086Z",
  "challenges": [{
    "type": "tls-sni-01",
    "status": "pending",
    "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/-gPc-DOOMPAqlaNV2_NCbwieC7cDgmsDxS4d0Ounp8A/5157173",
    "token": "rsFpjtnLgfXS8hMrAAcSsXJ98q7YNlA2Iyky-EWmoDY"
  }, {
    "type": "http-01",
    "status": "pending",
    "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/-gPc-DOOMPAqlaNV2_NCbwieC7cDgmsDxS4d0Ounp8A/5157174",
    "token": "w2iwBwQq2ByOTEBm6oWtq5nNydu3Oe0tU_H24X-8J10"
  }, {
    "type": "dns-01",
    "status": "pending",
    "uri": "https: //acme-v01.api.letsencrypt.org/acme/challenge/-gPc-DOOMPAqlaNV2_NCbwieC7cDgmsDxS4d0Ounp8A/5157175",
    "token": "U-85Krl7E2bPhqhdrjTuBoeIc7IVJ7Z4wyUhhn0uij0"
  }],
  "combinations": [
    [0],
    [2],
    [1]
  ]
}
```

Let's break this down. First our `"identifier"` is echoed back to us, along with its `"status"` - right now it's `"pending"` which means we haven't proven to LE that we control the domain; we're aiming to change it to `"valid"`. Our challenge also has an expiry date - 1 week from now at the time of writing.

```ruby
http_challenge, dns_challenge = ['http-01', 'dns-01'].map do |challenge_type|
  auth['challenges'].find { |challenge| challenge['type'] == challenge_type }
end
```

The `"uri"` of the challenge will allow us to notify LE that we're ready to take the challenge, on to check if we've passed. The `"token"` is a unique, unguessable, random value sent to us by LE that we'll need to **incorporate into our challenge response** to prove we control the domain.

`"combinations"` is a another feature that's designed for the future. Right now we only have to pass 1 challenge to convince LE we control the domain. In the future we might see something like this:

```json
"challenges": [{
  "type": "email-01",
  "..."
}, {
  "type": "http-01",
}, {
  "type": "tls-sni-01",
}, {
  "type": "dns-01",
}],
"combinations": [
  [0, 1],
  [2],
  [3]
]
```

Which would mean we'd have to either pass both challenges 0 & 1 (the `"email-01"` and `"http-01"` challenges), or challenge 2 or challenge 3 (`"tls-sni-01"` or `"dns-01"`).

<br>

#### c. Option 1: Completing the `http-01` challenge

Our first option is the `http-01` challenge. To pass this we need to ensure that when LE makes a request to 

`http://<< Domain >>/.well-known/acme-challenge/<< Challenge token >>`

They receive a specific response (more on that below). Our domain is `le.alexpeattie.com`, `.well-known/acme-challenge/` is a fixed path [defined](https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-7.2) by ACME, and our challenge token is `w2iwBwQq2ByOTEBm6oWtq5nNydu3Oe0tU_H24X-8J10`, so the endpoint we'll need to serve the response from is:

`http://le.alexpeattie.com/.well-known/acme-challenge/w2iwBwQq2ByOTEBm6oWtq5nNydu3Oe0tU_H24X-8J10`

##### The key authorization

First we'll create our **key authorization**: the special response LE expects to be served. It's quite simple - it's the challenge token and a 'thumbprint' of our public key joined with a period.

We're using the JSON Web Key standard to share details of our public key already (in the `jwk` field of our header). To generate the thumbprint we need to generate a digest of that JSON using `SHA256`, and Base64 encode it (see [RFC 7638](https://tools.ietf.org/html/rfc7638) for more).

Our final code for the `thumbprint` method looks like this:

```ruby
def thumbprint
  jwk = JSON.dump(header[:jwk])
  thumbprint = base64_le(hash_algo.digest jwk)
end
```

And for our final challenge response:

```ruby
http_challenge_response = [http_challenge['token'], thumbprint].join('.')
```

##### Uploading the challenge response

To prove to LE that we control a domain, `http://example.com/.well-known/acme-challenge/<< Challenge token >>` needs respond with `<< Challenge token >>.<< JWK thumbprint >>`. Because this is just a toy client, we'll create the file locally, then upload it (using [SCP](https://en.wikipedia.org/wiki/Secure_copy)) to our remote nginx server - a more usual approach would be to run the LE client on the server (so we can just write the necessary files directly to disk).

We'll use the [`net-scp` gem](https://github.com/net-ssh/net-scp) for easier SCP uploads:

```ssh
gem install net-scp
```

Since we're serving static files with nginx from `/usr/share/nginx/html`, so we'll first want to create the `.well-known/acme-challenge` directory:

```ssh
ssh root@162.243.201.152 'mkdir -p /usr/share/nginx/html/.well-known/acme-challenge'
```

The code for uploading the challenge is quite straightforward:

```ruby
require 'net/scp'

def upload(local_path, remote_path)
  server_ip = '162.243.201.152' # see Appendix 3
  Net::SCP.upload!(server_ip, 'root', local_path, remote_path) 
end

# ..
destination_dir = '/usr/share/nginx/html/.well-known/acme-challenge/'

IO.write('challenge.tmp', http_challenge_response)
upload('challenge.tmp', destination_dir + http_challenge['token']) and File.delete('challenge.tmp')
```

Our simple nginx setup (see [Appendix 3]((#appendix-3-our-example-site-setup))) serves static files (if they exist) for any endpoint, so this should be all we need to ensure that a request to `http://le.alexpeattie.com/.well-known/acme-challenge/w2iwBwQq2ByOTEBm6oWtq5nNydu3Oe0tU_H24X-8J10` returns our key authorization as its response (we can [verify this](http://le.alexpeattie.com/.well-known/acme-challenge/w2iwBwQq2ByOTEBm6oWtq5nNydu3Oe0tU_H24X-8J10) in a browser).

<br>

#### d. Option 2: Completing the `dns-01` challenge

The `dns-01` challenge was introduced at [the beginning of 2016](https://letsencrypt.org/upcoming-features/#acme-dns-challenge-support), allowing us to authorize our domain(s) by provisioning DNS records. The key differences between the `http-01` challenge and the `dns-01` challenge are:

- We'll add a DNS [TXT record](https://en.wikipedia.org/wiki/TXT_record) rather than uploading a file
- Rather than using "raw" key authorization as the record's contents, we'll use its (Base64 encoded) SHA-256 digest (see below)

There are lots of ways to add the required DNS record - most DNS services provide a web interface (instructions for common providers [here](http://help.campaignmonitor.com/topic.aspx?t=100#dns-providers)) - we'll be programatically adding a record using the [DNSimple API](https://developer.dnsimple.com/v1/) & [associated gem](https://github.com/aetrion/dnsimple-ruby/tree/master-v1).

The key ingredients of a DNS record are its type, name and value/contents. The type of the record is `TXT`, which is designed for adding arbitrary text data to a DNS zone. The name of the record takes the format `_acme-challenge.subdomain.example.com`. The root domain name is appended to a record's name automatically, so we just need to provide the name as `_acme-challenge.subdomain` or just `_acme-challenge` if we're authorization the root domain.

```ruby
record_name = '_acme-challenge.le'
```

To construct the contents of our record, we'll start by creating our "raw" challenge response in the same manner as in the `http-01` challenge:

```ruby
raw_challenge_response = [dns_challenge['token'], thumbprint].join('.')
```

Additionally, for the `dns-01` we'll need to digest the challenge response, and run it through our `base64_le` method:

```ruby
dns_challenge_response = base64_le(hash_algo.digest raw_challenge_response)
```

##### Adding the record

We'll use the [dnsimple-ruby gem](https://github.com/aetrion/dnsimple-ruby/tree/master-v1) to add our `TXT` record:

```shell
gem install dnsimple -v 2.2
```

We'll also need to get our API token from the [DNSimple web interface](https://dnsimple.com/user). Then using the gem to add the TXT record, with the correct record name & content. We'll set a relatively low TTL (time to live) of 60 seconds, because we don't want our resolvers to cache the record for long - in case we need to redo the challenge, for example.

```ruby
require 'dnsimple'

dnsimple = Dnsimple::Client.new(username: ENV['DNSIMPLE_USERNAME'], api_token: ENV['DNSIMPLE_TOKEN'])
challenge_record = dnsimple.domains.create_record('alexpeattie.com', {
  record_type: 'TXT',
  name: record_name,
  content: dns_challenge_response,
  ttl: 60
})
```

Lastly, we'll use Ruby's [Resolv](http://ruby-doc.org/stdlib-2.3.0/libdoc/resolv/rdoc/Resolv.html) library (part of the std lib) to wait until the challenge record's been added:

```ruby
loop do
  resolved_record = Resolv::DNS.open { |r| r.getresources(record_name + '.alexpeattie.com', Resolv::DNS::Resource::IN::TXT) }[0]
  break if resolved_record && resolved_record.data == challenge_response

  sleep 5
end
```

<br>

#### e. Telling LE we've completed the challenge

To tell LE we've completed the challenge, we need to make a request to the challenge URI we got earlier (`https://acme-v01.api.letsencrypt.org/acme/challenge/-gPc-DOOMPAqlaNV2_NCbwieC7cDgmsDxS4d0Ounp8A/5157174` or `/5157175`).

Our request needs to include the field `keyAuthorization` with the key authorization we've just generated:

```ruby
signed_request(http_challenge['uri'], { # or dns_challenge['uri']
  resource: 'challenge',
  keyAuthorization: http_challenge_response # or dns_challenge_response,
})
```

<br>

#### f. Wait for LE to acknowledge the challenge has been passed

Finally it's just a case of polling the challenge URI we've been given and wait for its status to become `"valid"`. If it's still `"pending"` we'll `sleep` for 2 seconds then try again. Any other status means something's gone wrong :sob:.

```ruby
loop do
  challenge_result = HTTParty.get(challenge['uri'])  # or dns_challenge['uri']

  case challenge_result['status']
    when 'valid' then break
    when 'pending' then sleep 2
    else raise "Challenge attempt #{ challenge_result['status'] }: #{ challenge_result['error']['details'] }"
  end
end
```

If we chose the DNS challenge, we should also clean up after ourselves by deleting the record (so our challenge attempt doesn't interfere with future challenge attempts, which will also require `TXT` records using the `_acme-challenge.le` name):

```ruby
dnsimple.domains.delete_record('alexpeattie.com', challenge_record.id)
```

<br>

## 5. Issuing the certificate :tada:

We've proven to Let's Encrypt we control the domain, which means we can now get our certificate. We'll need to generate a **Certificate signing request** (CSR). The CSR includes the public part of the key-pair tied to the certificate - secure traffic will be encrypted with the corresponding private part of the key-pair.

It's best to create a new key-pair for our CSR. We can generate it on the command line (as for the [client key-pair](#1-loading-our-client-key-pair)), or with Ruby:

```ruby
domain_key = OpenSSL::PKey::RSA.new(4096)
IO.write('domain.key', domain_key.to_pem)
```

**You might alternatively want to use a 2048 bit key (see [Appendix 5](#appendix-5-key-size) for more).*

Ruby's `OpenSSL` module makes the [generation of the CSR](http://ruby-doc.org/stdlib-2.3.0/libdoc/openssl/rdoc/OpenSSL.html#module-OpenSSL-label-Certificate+Signing+Request) very straightforward:

```ruby
csr = OpenSSL::X509::Request.new
csr.subject = OpenSSL::X509::Name.new([['CN', 'le.alexpeattie.com']])
csr.public_key = domain_key.public_key
csr.sign domain_key, hash_algo
```

We need to set the subject of the CSR - in this case the common name (domain name) we want to secure. Then we sign our certificate with our (private) `domain_key`.

LE needs us to send CSR in binary (.der) format - Base64 encoded of course. We'll be making a request for a `new-cert`:

```ruby
certificate_response = signed_request(endpoints['new-cert'], {
  resource: 'new-cert',
  csr: base64_le(csr.to_der),
})
```

Let's Encrypt should respond with our brand new, DV certificate :tada: :tada:. It's not quite ready to use though.

#### Formatting tweaks

Certificates should be typically enclosed by a `-----BEGIN CERTIFICATE-----` header and `-----END CERTIFICATE-----` (RFC [here](http://tools.ietf.org/html/rfc7468#section-2)) with each line wrapped at 64 characters. We could either do that manually (e.g. see [tiny-acme's](https://github.com/diafygi/acme-tiny/blob/master/acme_tiny.py) implementation) or let [`OpenSSL::X509::Certificate`](http://ruby-doc.org/stdlib-2.3.0/libdoc/openssl/rdoc/OpenSSL/X509/Certificate.html) take care of it:

```ruby
certificate = OpenSSL::X509::Certificate.new(certificate_response.body)
```

#### Adding intermediates

We also need to complete our trust chain, which means grabbing the LetsEncrypt cross-signed intermediate certificate (see <https://letsencrypt.org/certificates/>). Some browsers will resolve an incomplete trust chain, but it's something we want to avoid. There's much more info on why we need to complete this step and the difference between the different intermediates LE offers in [Appendix 2: The trust chain & intermediate certificates](#appendix-2-the-trust-chain--intermediate-certificates).

Occasionally server software might want us to provide our intermediate certificates separately, but generally we'll bundle them together in a single file. Helpfully, LE provides a link to the latest intermediate certificate in the certificate response's `Link` header (it has the relation type `"up"`):

```
Link: </acme/issuer-cert>;rel="up"
```

```ruby
intermediate = OpenSSL::X509::Certificate.new HTTParty.get(certificate_response.links.by_rel('up').target).body
IO.write('chained.pem', [certificate.to_pem, intermediate.to_pem].join("\n"))
```

That's it - we're done with our client and have our certificate (valid for the next 90 days) that will be accepted by all major browsers :white_check_mark:! Completed authorizations are valid for 300 days, so we can our renew certificate without needing to take a challenge during that period.

This is the end of the main part of the guide, if you're interesting in the logistics of installing the certificate, keep reading...

<br>
<hr>
<br>

## Appendix 1: Installing and testing the certificate

#### Installation (with nginx)

Now we have our certificate, it's just a case of uploading it along with our private key and tweaking our nginx configuration to enable TLS. As with our [HTTP challenge response](#uploading-the-challenge-response), we can upload the necessary files with SCP using our `upload` helper method:

```ruby
upload('chained.pem', '/etc/nginx/le-alexpeattie.pem')
upload('domain.key', '/etc/nginx/le-alexpeattie.key')
```

Then we'll need to point our `nginx.conf` to our certificate and key:

```nginx
server {
  listen 443 ssl deferred;
  server_name le.alexpeattie.com;

  ssl_certificate /etc/nginx/le-alexpeattie.pem;
  ssl_certificate_key /etc/nginx/le-alexpeattie.key;
}
```

That's theoretically all we need, but we can improve on nginx's defaults for better security and performance. We'll use the settings recommended by <https://cipherli.st/> (click "Yes, give me a ciphersuite that works with legacy / old software." if you need to support older browsers) and a couple of extra headers recommended by [securityheaders.io](https://securityheaders.io/). We'll use Google's DNS server (8.8.8.8) as our `resolver` (recommended for [OSCP stapling](https://en.wikipedia.org/wiki/OCSP_stapling) on nginx):

```nginx
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
ssl_ecdh_curve secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8;
resolver_timeout 5s;
# add_header Strict-Transport-Security "max-age=63072000; preload" always;
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src https: data: 'unsafe-inline' 'unsafe-eval'" always;
```

(Note: that the `Content-Security-Policy` header will prevent assets being loaded over HTTP - this is recommended, but could break some sites. Read more about CSPs [here](https://scotthelme.co.uk/content-security-policy-an-introduction/))

We should keep the line enabling the `Strict-Transport-Security` header commented out until we're happy our HTTPS setup is working (as visitor's won't be able to access our non-HTTPS site once it's activated).

We can harden our configuration by dropping support for TLS < v1.2 - although that does have implications for [supporting older browsers](https://en.wikipedia.org/wiki/Template:TLS/SSL_support_history_of_web_browsers). If we happy to target just older browsers, we should also allow only cipher suites with a minimum 256-bit key length for AES (the symmetric cipher):

```nginx
ssl_protocols TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers "AES256+EECDH:AES256+EDH";
```

Unless we're using an ECDSA certificate (see [Appendix 5](#appendix-5-key-size)) we should also generate a stronger DH parameter - nginx uses a 1024-bit prime which has been shown to be potentially vulnerable to state level adversaries (<https://weakdh.org>). Ideally our DH parameter shouldn't be smaller than our key size (i.e. 4096-bit or 2048-bit). We can generate a DH parameter like so:

```shell
ssh root@162.243.201.152

cd /etc/nginx
openssl dhparam -out dhparam.pem 4096
```

Bear in mind, the above is slooow (it took about 30 minutes for me) - so an alternative is to take a pre-generated prime [from here](https://2ton.com.au/dhtool/#service):

```bash
curl -o dhparam.pem https://2ton.com.au/dhparam/4096/`shuf -i 0-127 -n 1`
openssl dhparam -in dhparam.pem -noout -text | head -n 1
#=>    PKCS#3 DH Parameters: (4096 bit)
```

Either way we'll need to tell nginx to use our stronger DH parameter:

```nginx
ssl_dhparam /etc/nginx/dhparam.pem;
```

Lastly, we can redirect all HTTP traffic to our HTTPS endpoint:

```nginx
server {
  listen 80;
  server_name le.alexpeattie.com;
  return 301 https://$host$request_uri;
}
```

Our [final `nginx.conf`](https://github.com/alexpeattie/letsencrypt-fromscratch/blob/master/nginx.conf) looks like this:

```nginx
events {
  worker_connections  1024;
}

http {
  sendfile on;
  server_tokens off;
  root /usr/share/nginx/html;

  ssl_protocols TLSv1.2;
  ssl_prefer_server_ciphers on;
  ssl_ciphers "AES256+EECDH:AES256+EDH";
  ssl_ecdh_curve secp384r1;
  ssl_session_cache shared:SSL:10m;
  ssl_session_tickets off;
  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 8.8.8.8;
  resolver_timeout 5s;
  add_header Strict-Transport-Security "max-age=63072000; preload";
  add_header X-Frame-Options DENY;
  add_header X-Content-Type-Options nosniff;

  server {
    listen 443 ssl deferred;
    server_name le.alexpeattie.com;

    ssl_certificate /etc/nginx/le-alexpeattie.pem;
    ssl_certificate_key /etc/nginx/le-alexpeattie.key;
    ssl_dhparam /etc/nginx/dhparam.pem;
    ssl_trusted_certificate /etc/nginx/le-alexpeattie.pem;
  }

  server {
    listen 80;
    server_name le.alexpeattie.com;
    return 301 https://$host$request_uri;
  }
}
```

#### Testing

Lastly let's run some tests to ensure our certificates are correctly and securely installed. There are a few tools out there, [Qualys SSL Server Test](https://www.ssllabs.com/ssltest/) is the most widely used. Using our new certificate with the strict cipher list, with either an ECDSA certificate or a standard certificate with a 4096-bit DH param we'll net top marks with a perfect A+ score:

<p align='center'><img width="600" alt="A+ perfect score" src="https://cloud.githubusercontent.com/assets/636814/14065330/38b0c260-f41d-11e5-9e12-92b1b04adadf.png"></p>

Using [cipherli.st](https://cipherli.st/)'s recommended ciphers, we'll score fractionally lower, with 90 points Cipher Strength:

<p align='center'><img width="600" alt="A+ almost perfect score" src="https://cloud.githubusercontent.com/assets/636814/14065333/3e647d50-f41d-11e5-8784-de8ba408a033.png"></p>

We also do well on securityheader.io test:

<p align='center'><img width="600" alt="A grade on securityheaders.io" src="https://cloud.githubusercontent.com/assets/636814/20458341/193f8fc8-ae9a-11e6-8d18-05716f9c37ba.png"></p>

As the report points out, we can harden our set up even further by implementing [HTTP Public Key Pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning) which could protect us if, for instance, Let's Encrypt itself was successfully attacked. However, this is currently considered quite advanced: as [Peter Eckersley](https://www.eff.org/about/staff/peter-eckersley) warns "HPKP pinning carries an inherent risk of bricking your site". But he does give some [detailed best practices](https://community.letsencrypt.org/t/hpkp-best-practices-if-you-choose-to-implement/4625) for the brave souls who do want to implement it.

Some other useful testing tools:

- [revocationcheck.com](https://certificate.revocationcheck.com/) - Useful for debugging OSCP
- [testssl.sh](https://testssl.sh/) and [cipherscan](https://github.com/jvehent/cipherscan) - Command line TLS testing tools
- [SSL Decoder](https://ssldecoder.org) - Open-source tool for checking SSL/TLS config - gives lots of info, but no score per se.
- [High-Tech Bridge SSL Server Security Test](https://www.htbridge.com/ssl/) - A decent alternative to SSL Labs's tool. Advocates weaker ciphers because of HIPAA guidance though.

<br>

## Appendix 2: The trust chain & intermediate certificates

The trusted status of a certificate (what gives us the green padlock) stems from a relatively small set of trusted Certificate Authorities (CAs) with corresponding "Root certificates". These are stored in the "trust stores" of browsers or operating systems. We can see Mac OS's trusted roots by going to *Keychain Access* -> *System Roots* for example:

If our certificate has been issued by a trusted CA (in our trust store) that certificate is trusted. If the CA isn't in our trust store, we can check if certificate of **that** CA was issued by a trusted root CA. A certificate issued by a CA, issued by another CA which was issued by a trusted CA is trusted, and so on. The trust chain can involve as many untrusted or "intermediate" CAs as we want, as long as it ultimately goes back to a trusted (root CA).

If it's still unclear, imagine Alice & Bob are having a birthday party. Guests who are invited by Alice or Bob can in turn invite other guests - those guests can invite other guests and so on. At the party, only guests who can prove their invitation leads back to Alice and Bob are trusted:

- Carol ← invited by Bob = trusted :white_check_mark:
- Doug ← invited by Steve ← invited by Alice = trusted :white_check_mark:
- Fred ← invited by Gerard ← invited by Eve = untrusted :no_entry:

At the party, a guest would have to provide information so we could verify the chain of invites led back to Alice or Bob. In the same way, a certificate should provide information about the chain of certificates (called the trust chain) which lead back to a trusted root CA. 

In the future Let's Encrypt hopes to have its own trusted root CA: [ISRG Root X1](https://letsencrypt.org/certificates/). Right now ISRG Root X1 isn't trusted by any browsers or operating systems - so IdenTrust is acting as their root CA instead. Let's Encrypt's intermediate CA is issued directly by Identrust's root CA (which is trusted by all major browsers/OSes) so our trust chain is only three links long:

- Our certificate ← issued by Let's Encrypt CA ← 'issued' by Identrust CA

'Issued' is a bit of oversimplification here - in fact, Identrust just cross-signed LE's CA certificate, but it achieves the same end-result: trust in all major browsers/OSes.

So our complete trust chain should include our certificate, the [certificate of Let's Encrypt's intermediate CA](https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt) (Let’s Encrypt Authority X3), and optionally the Identrust CA's [trusted root certificate](https://raw.githubusercontent.com/EFForg/https-everywhere/master/cert-validity/mozilla/builtin-certs/DST_Root_CA_X3.crt). In reality there's no point making the client download the root certificate - it needs to already be in the trust store anywhere. As RFC 2246 says:

> Because certificate validation requires that root keys be distributed independently, the self-signed certificate which specifies the root certificate authority may optionally be omitted from the chain, under the assumption that the remote end must already possess it in order to validate it in any case.

So basically we just need to concatenate our certificate with Let's Encrypt CA's certificate and we have a complete chain of trust* :+1:.

FF 44 | Chrome 48 | IE 11 | Safari 7.1 | iOS 8 (Safari) | Windows Phone 8.1 | Android 6
--- | --- | --- | --- | --- | --- | ---
:white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:

**Some servers (like Apache) might want us to provide the our certificate and the rest of the trust chain separately. In this case the rest of the chain would just be the LE intermediate certificate.*

#### Missing certificate chain

If we only provide our certificate without LE's intermediate certificate, we have a **broken chain of trust**. Most browsers can actually recover from this. LE certificates leverage *Authority Information Access* which embeds information about the trust chain even if we (system admins) forget to provide it.

We shouldn't rely on this though, most mobile browsers don't support AIA - nor does Firefox (who have explicitly said they [won't be adding it](https://bugzilla.mozilla.org/show_bug.cgi?id=399324)).

Here's the result you'll get without providing the intermediate certificate:

FF 44 | Chrome 48 | IE 11 | Safari 7.1 | iOS 8 (Safari) | Windows Phone 8.1 | Android 6
--- | --- | --- | --- | --- | --- | ---
:no_entry: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :no_entry: | :no_entry: | :no_entry:

#### LE root certificate

Let's Encrypt has it's own root certificate authority that's separate from Identrust, called ISRG Root X1. When this root CA is widely trusted, expect it to take Identrust's place in the trust chain. We can already use an [intermediate certificate issued by ISRG Root X1](https://letsencrypt.org/certs/letsencryptauthorityx1.pem.txt) - the problem is that, at the time of writing, ISRG Root X1 isn't trusted anywhere (to my knowledge).

If we try using the LE root-signed intermediate now, most browsers that support AIA will fallback to the valid trust chain, except desktop Safari.

FF 44 | Chrome 48 | IE 11 | Safari 7.1 | iOS 8 (Safari) | Windows Phone 8.1 | Android 6
--- | --- | --- | --- | --- | --- | ---
:no_entry: | :white_check_mark: | :white_check_mark: | :no_entry: | :no_entry: | :no_entry: | :no_entry:

<br>

## Appendix 3: Our example site setup

Below are the instructions to recreate the site setup used as the exemplar in this guide. You'll need:

- A domain name you control
- A [DNSimple](https://dnsimple.com/) account (from $5/month, 30 day trial)
- A [DigitalOcean](https://www.digitalocean.com/) droplet (from $5/month)

#### 1. Point our domain's nameservers to DNSimple

Digital Ocean has [good instructions](https://www.digitalocean.com/community/tutorials/how-to-point-to-digitalocean-nameservers-from-common-domain-registrars) that cover common registrars. We'll want to point the nameservers to `ns1.dnsimple.com`, `ns2.dnsimple.com`, `ns3.dnsimple.com` and `ns4.dnsimple.com`. You'll need to copy over any existing records from your previous DNS provider.

#### 2. Create our nginx server

First we'll need to [create our droplet](https://cloud.digitalocean.com/droplets/new). We'll use a $5/month Ubuntu droplet:

<img width="500" alt="Creating droplet" src="https://cloud.githubusercontent.com/assets/636814/13723480/be2f67d6-e85e-11e5-9695-376c0bf595b3.png">

We'll also want to add our local machine's SSH key(s). We want to paste the public part of our key (e.g. `cat ~/.ssh/id_rsa.pub`):

<img width="700" alt="Adding SSH key" src="https://cloud.githubusercontent.com/assets/636814/13723546/b0059732-e860-11e5-9e62-ab8306233377.png">

Once our machine has been provisioned, take a note of the public IP, in this case 162.243.201.152:

<img width="300" alt="Droplet's public IP" src="https://cloud.githubusercontent.com/assets/636814/13723553/da28e8e8-e860-11e5-82a4-b29b702acc10.png">

Using the IP, we'll SSH into our new box and install [nginx](http://nginx.org/):

```shell
ssh root@162.243.201.152

add-apt-repository ppa:nginx/stable
apt-get update
apt-get install nginx
```

A configuration like the below will be sufficient for passing the challenges - we'll update it when we actually install our certificate. This needs to go in `/etc/nginx/nginx.conf`:

```nginx
events {
  worker_connections  1024;
}

http {
  sendfile on;
  server_tokens off;
  root /usr/share/nginx/html;

  server {
    listen 80;
    server_name le.alexpeattie.com;
  }
}
```

Lastly we'll restart nginx:

```shell
sudo service nginx restart
```

#### 4. Point our subdomain to DigitalOcean

Log in to DNSimple, go to **Domains** and hit DNS in the sidebar:

![DNSimple sidebar](https://cloud.githubusercontent.com/assets/636814/13373722/649bb5a0-dd67-11e5-80db-bc24771e6f7a.png)

The click **+ Manage records**. We want to add an A record:

![Add A record](https://cloud.githubusercontent.com/assets/636814/13723619/96c2d21a-e862-11e5-97f4-ceb03f07b6e7.png)

We'll need to enter the name (our subdomain `le`) and set **Address** to our droplet's Public IP:

![Configure A](https://cloud.githubusercontent.com/assets/636814/13723623/b1a0178c-e862-11e5-83fb-92c878dd5b4d.png)

We should be ready to go, and the domain (e.g. <le.alexpeattie.com>) should serve the default nginx welcome page. We might have to wait a while for our DNS changes to propagate.

<p align='center'><img src="https://cloud.githubusercontent.com/assets/636814/13723640/6181806e-e863-11e5-8889-838f1d333da7.png" alt="nginx welcome"></p>

Once we've been issued our certificate, we can install it following [the steps in Appendix 1](#installation-with-nginx).

<br>

## Appendix 4: Multiple subdomains

Let's Encrypt can issue a single certificates which cover multiple, using the [SubjectAltName extension](https://en.wikipedia.org/wiki/SubjectAltName). At the time of writing, Let's Encrypt supports a maximum of 100 SANs per certificate (full LE rate limits are detailed [here](https://letsencrypt.org/docs/rate-limits/)).

LE has quite conservative per-domain rate limits right now (5 certificates per domain per week) - so using SANs is crucial if you have lots of subdomains to secure*. [**LE doesn't currently support wildcard certificates**](https://letsencrypt.org/docs/faq#will-lets-encrypt-issue-wildcard-certificates).

A common use-case is having a single certificate cover the naked domain and `www.` prefix. We have to authorize both domains; LE doesn't take it for granted that if we control the root domain we also control the `www.` subdomain or vice-versa.

```ruby
domains = %w(example.com www.example.com)

domains.each do |domain|
  auth = signed_request(endpoints['new-authz'], {
    resource: 'new-authz',
    identifier: {
      type: 'dns',
      value: domain
    }
  })

  #.. rest of challenge passing code
end
```

Once we've authorized all the subdomains we want to include in the certificate, we can modify our CSR to use the SAN extension (warning: not the prettiest or most readable code you'll ever see):

```ruby
alt_names = domains.map { |domain| "DNS:#{domain}" }.join(', ')

extension = OpenSSL::X509::ExtensionFactory.new.create_extension('subjectAltName', alt_names, false)
csr.add_attribute OpenSSL::X509::Attribute.new(
  'extReq',
  OpenSSL::ASN1::Set.new(
    [OpenSSL::ASN1::Sequence.new([extension])]
  )
)
```

That's all you need to get certificates to cover multiple host names, you can find the full code of the example in [`multiple_subdomains.rb`](https://github.com/alexpeattie/letsencrypt-fromscratch/blob/master/multiple_subdomains.rb).

**If you're running a site that, say, assigns thousands of subdomains to end users you may be out of luck, unless you can get your domain added to [Public Suffix list](https://publicsuffix.org/) - which LE treats as a [special case](https://github.com/letsencrypt/boulder/issues/1374).*

<br>

## Appendix 5: Key size

Broadly-speaking key size means how hard a key is to crack. Longer keys offer more security, but their bigger size leads to a somewhat slower TLS handshake.

<p align='center'><a href='https://certsimple.com/blog/measuring-ssl-rsa-keys'><img src='https://certsimple.com/images/blog/measuring-rsa-keys/handshake-speed.png' alt='SSL handshake speed at different key sizes'></a></p>

We don't have a very broad choice when it comes to choosing key size. 2048 bits has effectively been an [enforced minimum](https://www.cabforum.org/wp-content/uploads/Baseline_Requirements_V1.pdf) since the beginning of 2014; 4096 bits is the upper bound. 4096 bits is favored by some, but is far from the standard right now. It's anticipated that 2048-bit keys will be considered secure [until about 2030](http://www.keylength.com/en/4/).

2048 is the default key size for [cerbot](https://github.com/certbot/certbot#current-features). But you will need a 4096 bit key to score perfectly on the Key [SSL Labs' test](https://www.ssllabs.com/downloads/SSL_Server_Rating_Guide.pdf), and there are lively discussions advocating the LE default be raised to [4096](https://github.com/certbot/certbot/issues/489) or [3072](https://github.com/certbot/certbot/issues/2080). CertSimple did an [awesome, detailed rundown](https://certsimple.com/blog/measuring-ssl-rsa-keys) of the benefits of different key sizes, and basically concluded "it depends".

We will need a key size of 4096 bits to get a perfect SSL Labs score. Not all cloud providers support key sizes about 2048 bits though, AWS CloudFront being a notable example. If you want or need to use a 2048-bit key, you can specify the key length like so:

```ruby
domain_key = OpenSSL::PKey::RSA.new(2048)
```

### ECDSA keys

If you really care about picking a good key, you might not want to use RSA at all. ECDSA ([Elliptic Curve Digital Signature Algorithm](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)) which gives a much better size vs. security trade-off. A 384 bit ECDSA is considered equivalent to a [7680 bit RSA key](http://crypto.stackexchange.com/questions/2482/how-strong-is-the-ecdsa-algorithm), and will also give a perfect SSL Labs score. More importantly, a number recently discovered SSL vulnerabilities (DROWN, Logjam, FREAK) target RSA-specific vulnerabilities which are not present in ECDSA certificates.

We'll have to a bit more work to create an ECDSA CSR (see [this blog post I wrote](https://alexpeattie.com/blog/signing-a-csr-with-ecdsa-in-ruby) for a more detailed explanation):

```ruby
# monkey patch to fix https://redmine.ruby-lang.org/issues/5600
OpenSSL::PKey::EC.send(:alias_method, :private?, :private_key?)

domain_key = OpenSSL::PKey::EC.new('secp384r1').generate_key
IO.write('domain.key', domain_key.to_pem)

csr = OpenSSL::X509::Request.new
csr.subject = OpenSSL::X509::Name.new(['CN', 'le.alexpeattie.com'])
csr.public_key = OpenSSL::PKey::EC.new(domain_key)
csr.sign domain_key, OpenSSL::Digest::SHA256.new
```

ECDSA is pretty well supported: Windows Vista and up, OS X 10.9, Android 3 and iOS 7*

**Source: [CertSimple: What web developers should know about SSL but probably don't](https://certsimple.com/blog/obsolete-cipher-suite-and-things-web-developers-should-know-about-ssl)*

<br>

## Appendix 6: IDN support

Since October 2016 Let's Encrypt has [supported Internationalized Domain Names](https://letsencrypt.org/upcoming-features#idn-support) (IDNs). When providing an IDN as the `identifier`'s `value` in our `new-authz` request, and when setting the subject of the CSR, we need to use the [Punycode](https://en.wikipedia.org/wiki/Punycode) representation of the IDN. For example, `müller.de` would become `xn--mller-kva.de`.

You can do the conversion with an online service like [Punycoder](https://www.punycoder.com/) or with a gem like [SimpleIDN](https://github.com/mmriis/simpleidn):

```ruby
require 'simpleidn'

domain = SimpleIDN.to_unicode('müller.de')
=> 'xn--mller-kva.de'
```

<br>

## Further reading

#### TLS/SSL in general

- [Bulletproof SSL and TLS](https://www.feistyduck.com/books/bulletproof-ssl-and-tls/) - wonderful ~500 page book, goes into great detail about everything you might want to know about SSL/TLS
- [SSL/TLS Deployment Best Practices (PDF)](https://www.ssllabs.com/downloads/SSL_TLS_Deployment_Best_Practices.pdf) - By the same author as *Bulletproof*, a quick 10 page checklist
- [TLS chapter in High Performance Browser Networking](http://chimera.labs.oreilly.com/books/1230000000545/ch04.html) - like the TL;DR of *Bulletproof*, covers all the fundamentals, plus more recent developments like OCSP stapling, HSTS etc.
- [OWASP's TLS Cheat Sheet](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet) - An excellent list of do's and don't relating to SSL/TLS
- [Modern SSL/TLS Best Practices for Fast, Secure Websites](http://www.scmagazine.com/resource-library/resource/cloudflare/whitepaper/56cb65bced344a22f86cb85d/) (PDF, registration required) - decent white paper, with loads of visuals, up-to-date best practice recommendations
- [SSL Best Practices: a Quick and Dirty Guide](https://www.ssl.com/guide/ssl-best-practices-a-quick-and-dirty-guide/) - top-level, reasonably recent (2015) best practices guide.
- [How does SSL/TLS work?](http://security.stackexchange.com/questions/20803/how-does-ssl-tls-work/20833#20833) - Good StackExchange answer
- [TLS in HTTP/2](https://daniel.haxx.se/blog/2015/03/06/tls-in-http2/)

#### Let's Encrypt

- [ACME spec](https://tools.ietf.org/html/draft-ietf-acme-acme-01) - technical spec of the ACME protocol (which LE is built on)
- [acme-tiny](https://github.com/diafygi/acme-tiny) - a < 200 line Python client that served as the inspiration for this guide. The source code is v. readable + well commented
- [Let's Encrypt - How It Works](https://letsencrypt.org/how-it-works/) - official LE article
- [Let's Encrypt Overview](https://www.cryptologie.net/article/274/lets-encrypt-overview/) - good detailed article written back in 2015 when LE was starting out
- [Let's Encrypt - A Certificate Authority To Encrypt the Entire Web (video)](https://www.youtube.com/watch?v=pd-h8WOiI8A)
- [Using Free SSL/TLS Certificates from Let's Encrypt with NGINX](https://www.nginx.com/blog/free-certificates-lets-encrypt-and-nginx/)
- [Pros and cons of 90-day certificate lifetimes](https://community.letsencrypt.org/t/pros-and-cons-of-90-day-certificate-lifetimes/4621)

<br>

## Image credits

- Key - [Pixabay](https://pixabay.com/en/skeleton-key-key-old-lock-vintage-303535/)
- Nonce - [chibird](http://chibird.com/post/27665010997/sometimes-youre-really-reminded-how-precious-life)

<br>

## Author

<img src='https://avatars3.githubusercontent.com/u/636814?v=3&s=100'>

Alex Peattie / [alexpeattie.com](https://alexpeattie.com/) / [@alexpeattie](https://twitter.com/alexpeattie) 

<br>

## Changelog

#### Version 1.1 - Nov 19 2016
* Use the directory and response headers, rather than hardcoding URIs (closes [#1](https://github.com/alexpeattie/letsencrypt-fromscratch/issues/1))
* Add Appendix 6 about newly supported Internationalized Domain Names
* Change reference to official Let's Encrypt client → certbot
* Specify a TTL for DNS challenge record
* Add note about certificate and authorization validity periods
* Consistently prefer single quotes in all Ruby code
* Remove example domains for the various certificate types
* Added a couple more tools to the Testing section
* Add Changelog & Author section
* Harden example nginx config with additional security headers

#### Version 1.0 - Mar 29 2016
* Initial release
