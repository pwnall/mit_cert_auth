# Controller for showing the public signing key and the documentation homepage.
# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT


class DocumentationController < ApplicationController
  # Shows the documentation page.
  #
  # GET /index.html
  def index
    
  end
  
  # Dumps the public key.
  #
  # GET /pubkey.js?callback=cbMethod
  # GET /pubkey.pem
  def pubkey
    @pubkey = self.class.key_holder.key.public_key
    
    respond_to do |format|
      format.json do
        render :json => { :key => @pubkey.to_pem },
               :callback => params[:callback]
      end
      format.pem { render :text => @pubkey.to_pem }
      # TODO: perhaps support the .pub format (for authorized_keys)
    end
  end
end
