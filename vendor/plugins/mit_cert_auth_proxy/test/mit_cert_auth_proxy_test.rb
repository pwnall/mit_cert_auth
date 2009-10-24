# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT

require 'test_helper'
require 'flexmock/test_unit'


class MitCertAuthProxyTest < ActiveSupport::TestCase
  def test_mit_ca_paths
    [['mit_ca_path', MitCertAuthProxy.mit_ca_path],
     ['mit_scripts_path', MitCertAuthProxy.mit_scripts_ca_path]
    ].each do |path_name, ca_path|
      assert ca_path, "#{path_name} is nil"
      assert File.read(ca_path), "cannot read from #{path_name}?"
    end
  end
  
  def test_redirect_url
    data = {:s => :win, 't u' => 'also win'}
    [['http://www.awesome.com', 'http://www.awesome.com?s=win&t+u=also+win'],
     ['http://mit.edu/', 'http://mit.edu/?s=win&t+u=also+win'],
     ['http://mit.edu/page', 'http://mit.edu/page?s=win&t+u=also+win'],
     ['http://mit.edu/page?q=one',
      'http://mit.edu/page?q=one&s=win&t+u=also+win']
    ].each do |base_url, golden_url|
      assert_equal golden_url,
                   MitCertAuthProxy.redirect_url(base_url, data).to_s,
                   "Failed on #{base_url}"
    end    
  end

  def test_signing_key
    key = MitCertAuthProxy.signing_key
    assert_operator key, :kind_of?, OpenSSL::PKey::PKey,
                    'Did not fetch a key'
    assert !key.private?, 'The key is private; probably fetched the wrong key'
  end
  
  def test_sign_and_verify
    key = OpenSSL::PKey::RSA.generate 512
    data = {:a => 1, :b => 2, :c => 3}
    MitCertAuthProxy.sign_data! key, data
    assert data['signature'], 'Did not sign'

    flexmock(MitCertAuthProxy).should_receive(:signing_key).
                               and_return(key.public_key)
    assert MitCertAuthProxy.verify_data(data), "Valid signature didn't verify"
    data[:c] = 4
    assert !MitCertAuthProxy.verify_data(data), "Invalid signature verified"    
  end
  
  def test_random_nonce
    nonces = Set.new(Array.new(1000) { MitCertAuthProxy.random_nonce })
    assert_equal 1000, nonces.length, 'Nonces are not random enough'
  end
  
  def test_auth_url_redirecting_to
    flexmock(MitCertAuthProxy).should_receive(:random_nonce).and_return('1234').
                               once
    golden_url = 'https://costan.scripts.mit.edu:444/mit_cert_auth/auth?' +
        'redirect_to=http%3A%2F%2Fwww.a.com&nonce=1234'
    assert_equal URI.parse(golden_url),
                 MitCertAuthProxy.auth_url_redirecting_to('http://www.a.com'),
                 'implicit nonce'
    assert_equal URI.parse(golden_url),
                 MitCertAuthProxy.auth_url_redirecting_to('http://www.a.com',
                                                          '1234'),
                 'exmplicit nonce'
  end

  def test_auth_url_calling
    flexmock(MitCertAuthProxy).should_receive(:random_nonce).and_return('1234').
                               once
    golden_url = 'https://costan.scripts.mit.edu:444/mit_cert_auth/auth.json?' +
        'callback=callbackMethod&nonce=1234'
    assert_equal URI.parse(golden_url),
                 MitCertAuthProxy.auth_url_calling('callbackMethod'),
                 'implicit nonce'
    assert_equal URI.parse(golden_url),
                 MitCertAuthProxy.auth_url_calling('callbackMethod', '1234'),
                 'eximplicit nonce'
  end
end
