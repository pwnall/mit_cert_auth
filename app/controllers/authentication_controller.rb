# The controller that handles the authentication requests (/auth).
# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT


class AuthenticationController < ApplicationController
  # Outputs the result of the MIT certificate authentication.
  #
  # GET /auth.json?nonce=123&callback=cbMethod
  # GET /auth?nonce=123&redirect_to=http%5A....
  def auth
    @signed_auth_data = @auth_data.merge :nonce => params[:nonce]
    MitCertAuthProxy.sign_data! self.class.key_holder.key, @signed_auth_data
    
    respond_to do |format|
      format.html do
        redirect_to_full_url MitCertAuthProxy.redirect_url(
            params[:redirect_to], @signed_auth_data).to_s, :found
      end
      format.json do
        render :json => @signed_auth_data, :callback => params[:callback]
      end
    end
  end
end
