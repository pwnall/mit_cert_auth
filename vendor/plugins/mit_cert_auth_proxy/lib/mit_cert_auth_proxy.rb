# Response signing logic for the MIT certificate authentication proxy. 
# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT

require 'cgi'
require 'openssl'
require 'uri'
require 'net/http'
require 'net/https'


module MitCertAuthProxy
  # An URL to the authentication service which will result in a HTTP redirect.
  #
  # This is most useful in iframes.
  def self.auth_url_redirecting_to(url, nonce = nil)
    nonce ||= random_nonce
    base_uri.merge 'auth?redirect_to=' + CGI.escape(url) +
                   '&nonce=' + CGI.escape(nonce)
  end
    
  # Computes a redirection URL from a base URL and query parameters that should
  # be appended to it.
  #
  # This method should only be useful in the authentication proxy itself.
  def self.redirect_url(base_url, signature_data)
    url = URI.parse base_url
    url.query ||= ''
    url.query += '&' unless url.query.empty?
    # NOTE: the "sort" call is only there for determinism.
    url.query += signature_data.map { |k, v|
      CGI.escape(k.to_s) + '=' + CGI.escape(v.to_s)
    }.sort.join '&'
    url
  end
  
  # An URL to the authentication service which will return JSONP.
  #
  # This is most useful in <script> tags.
  def self.auth_url_calling(callback_name, nonce = nil)
    nonce ||= random_nonce
    base_uri.merge 'auth.json?callback=' + CGI.escape(callback_name) +
                   '&nonce=' + CGI.escape(nonce)
  end
  
  # A random nonce for invoking the authentication service.
  #
  # The nonce will be included in the signed authentication data and can be used
  # to prevent replay attacks.
  def self.random_nonce
    [OpenSSL::Random.random_bytes(16)].pack('m')    
  end
    
  # Checks authentication data.
  #
  # This method will automatically download the proxy's public key, if
  # necessary. 
  def self.verify_data(data)
    signature = data['signature'].unpack('m').first
    blob = _presign_blob data
    signing_key.verify OpenSSL::Digest::SHA1.new, signature, blob
  end
  
  # Signs authentication data.
  #
  # The signature will be added directly to the authentication data.
  #
  # This should only be called by the authentication proxy itself. Other library
  # users won't have the private signing key, so they won't get much use out of
  # this method.
  def self.sign_data!(private_sign_key, data)
    blob = _presign_blob data    
    raw_signature = private_sign_key.sign OpenSSL::Digest::SHA1.new, blob
    data['signature'] = [raw_signature].pack('m')
  end
  
  # Computes the blob of text to be signed.
  def self._presign_blob(data)
    data.map { |key, value| [key.to_s, value.to_s] }.
         select { |key, value| key.to_s != 'signature' }.sort.join("\n")
  end
  
  # The proxy's signing key.
  #
  # This key is used by verify_data to certify the source of proxied
  # authentication data.
  def self.signing_key
    @signing_key ||= fetch_sign_key
  end
  
  # Fetches the signing key from MIT's server. 
  def self.fetch_sign_key
    [mit_scripts_ca_path, mit_ca_path, '/etc/ssl/certs'].each do |ca_path|
      begin
        return fetch_sign_key_with_ca ca_path
      rescue OpenSSL::SSL::SSLError
        # This CA source didn't work, try the next one. 
      end
    end
    nil
  end
  
  # Fetches the signing key from MIT's server using CA data from a fixed source. 
  def self.fetch_sign_key_with_ca(ca_path)
    sign_uri = base_uri.merge 'pubkey.pem'
    
    # Ensure the signing key comes from a trusted source.
    http = Net::HTTP.new sign_uri.host, sign_uri.port
    http.use_ssl = true
    if File.directory? ca_path
      http.ca_path = ca_path
    else
      http.ca_file = ca_path
    end
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.verify_depth = 6

    request = Net::HTTP::Get.new sign_uri.request_uri    
    response = http.request request
    OpenSSL::PKey::RSA.new response.body
  end
  
  # Path to the Certificate Authority file used on scripts.mit.edu.
  #
  # The CA file is shipped with this gem for poor Windows souls who don't have
  # an /etc/ssl/certs.
  def self.mit_scripts_ca_path
    File.join File.dirname(__FILE__), 'equifaxca.pem'
  end

  # Path to MIT's Certificate Authority file.
  #
  # The CA file is shipped with this gem because MIT uses a self-signed CA, so
  # most systems don't have a trust chain to MIT certificates.
  def self.mit_ca_path
    File.join File.dirname(__FILE__), 'mitca.crt'
  end
  
  # The base URI of the MIT certificate authentication proxy service.
  def self.base_uri
    SERVICE_URI
  end
  SERVICE_URI = URI.parse "https://costan.scripts.mit.edu:444/mit_cert_auth/"
end
