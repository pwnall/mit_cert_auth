# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT

require 'test_helper'
require 'flexmock/test_unit'


class AuthenticationControllerTest < ActionController::TestCase
  def setup
    super
    @nonce = 'O9eYWU/t1NSb+ZDmfniqizBSeNhVtsnTHS1H3T2FtRc='
    @dn = 'costan@mit.edu'
    @request.env['SSL_CLIENT_S_DN'] = @dn
  end
  
  def test_auth_with_redirect
    get :auth, :nonce => @nonce, :redirect_to => 'http://www.awesome.com/auth'
    golden_url = 'http://www.awesome.com/auth?auth%5Bdn%5D=costan%40mit.edu' +
      '&auth%5Bnonce%5D=' + CGI.escape(@nonce) + '&auth%5Bsignature%5D='
    assert_response :redirect
    url = @response.redirect_url
    assert_equal golden_url, url[0, golden_url.length], 'Invalid golden URL'
    _check_signature_data 'dn' => @dn, 'nonce' => @nonce,
         'signature' => URI.decode(url.to_s[golden_url.length..-1])
  end
    
  def test_auth_with_callback
    get :auth, :nonce => @nonce, :callback => 'cbMethod', :format => 'json'
    json = /^cbMethod\((.*)\);?$/.match(@response.body)[1]
    data = JSON.load(json)
    
    assert_equal @dn, data['dn'], 'DN'
    assert_equal @nonce, data['nonce'], 'Nonce'
    _check_signature_data data
  end

  def _check_signature_data(data)
    flexmock(MitCertAuthProxy).should_receive(:signing_key).
                               and_return(SignKeyHolder.new.key.public_key)
    assert MitCertAuthProxy.verify_data_signature(data), 'Invalid signature'
  end
end
