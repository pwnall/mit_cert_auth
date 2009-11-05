# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT

require 'test_helper'
require 'json'


class DocumentationControllerTest < ActionController::TestCase
  def test_index
    get :index
    assert_response :success
  end
  
  def _check_sign_key(sign_key_pem)
    sign_key = OpenSSL::PKey::RSA.new sign_key_pem
    assert !sign_key.private?, 'Private key leaked!'
    assert_equal SignKeyHolder.new.key.public_key.inspect, sign_key.inspect,
                 'Wrong key returned'    
  end
  
  def test_pubkey_pem
    get :pubkey, :format => 'pem'
    assert_response :success
    
    _check_sign_key @response.body
 end
    
  def test_pubkey_json
    get :pubkey, :format => 'json', :callback => 'cbMethod'
    assert_response :success
    
    json = /^cbMethod\((.*)\);?$/.match(@response.body)[1]
    _check_sign_key JSON.load(json)['key']
  end
end
