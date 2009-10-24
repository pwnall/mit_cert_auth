# Application controller with a filter decoding the SSL environment variables.
# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT


# Filters added to this controller apply to all controllers in the application.
# Likewise, all the methods added will be available for all controllers.
class ApplicationController < ActionController::Base
  helper :all # include all helpers, all the time
  protect_from_forgery # See ActionController::RequestForgeryProtection for details

  # Scrub sensitive parameters from your log
  # filter_parameter_logging :password
  
  before_filter :decode_certificate
  def decode_certificate
    @auth_data = {}    
    request.headers.each do |key, value|
      next unless translated_key = CERTIFICATE_KEYS[key]
      @auth_data[translated_key] = value
    end
  end
  
  CERTIFICATE_KEYS = {
    'SSL_CLIENT_S_DN' => :dn,
    'SSL_CLIENT_I_DN' => :issuer_dn,
    'SSL_CLIENT_M_SERIAL' => :serial,
    'SSL_CLIENT_V_START' => :valid_from,
    'SSL_CLIENT_V_END' => :valid_until,
    
    'SSL_CLIENT_VERIFY' => :verify,
    'SSL_CLIENT_A_SIG' => :ssl_sig,
    'SSL_PROTOCOL' => :protocol,
    'SSL_CIPHER' => :cipher,    
  }
  
  # Signing key holder.
  def self.key_holder
    @key_holder ||= SignKeyHolder.new
  end  
end
