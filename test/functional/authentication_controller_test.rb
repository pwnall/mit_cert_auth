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
    golden_url = 'http://www.awesome.com/auth?dn=costan%40mit.edu&nonce=' +
      CGI.escape(@nonce) + '&signature='
    assert_response :redirect
    url = @response.redirect_url
    assert_equal golden_url, url[0, golden_url.length], 'Invalid golden URL'
    _check_signature URI.decode(url[golden_url.length..-1])
  end
    
  def test_auth_with_callback
    get :auth, :nonce => @nonce, :callback => 'cbMethod', :format => 'json'
    json = /^cbMethod\((.*)\);?$/.match(@response.body)[1]
    data = JSON.load(json)
    
    assert_equal @dn, data['dn'], 'DN'
    assert_equal @nonce, data['nonce'], 'Nonce'
    _check_signature data['signature']
  end

  def _check_signature(signature)
    flexmock(MitCertAuthProxy).should_receive(:signing_key).
                               and_return(SignKeyHolder.new.key.public_key)
    data = {'dn' => @dn, 'nonce' => @nonce, 'signature' => signature}
    assert MitCertAuthProxy.verify_data(data), 'Invalid signature'
  end
end
