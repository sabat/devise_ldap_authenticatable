require "net/ldap"

module Devise

  module LdapAdapter
    
    def self.valid_credentials?(login, password_plaintext)
      options = {:login => login, 
                 :password => password_plaintext, 
                 :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                 :admin => ::Devise.ldap_use_admin_to_bind}
                 
      resource = LdapConnect.new(options)
      resource.authorized?
    end
    
    def self.update_password(login, new_password)
      options = {:login => login,
                 :new_password => new_password,
                 :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                 :admin => ::Devise.ldap_use_admin_to_bind}
                 
      resource = LdapConnect.new(options)
      resource.change_password! if new_password.present? 
    end
    
    def self.get_groups(login)
      options = {:login => login, 
                 :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                 :admin => ::Devise.ldap_use_admin_to_bind}

      ldap = LdapConnect.new(options)
      ldap.user_groups
    end
    
    def self.get_dn(login)
      options = {:login => login, 
                 :ldap_auth_username_builder => ::Devise.ldap_auth_username_builder,
                 :admin => ::Devise.ldap_use_admin_to_bind}
      resource = LdapConnect.new(options)
      resource.dn
    end

    class LdapConnect

      attr_reader :ldap, :login

      def initialize(params = {})
        # bug found: this only loads YAML from *environment* section, although the
        # ldap.yml file has an example outside of the environment section.
        # Fix is to merge in the hash inside 'authorizations' from general section.
        f = File.read(::Devise.ldap_config || "#{Rails.root}/config/ldap.yml")
        ldap_config = YAML.load(ERB.new(f).result)[Rails.env]
        ldap_config.merge!( YAML.load(ERB.new(f).result)['authorizations'] ) unless ldap_config.has_key?('authorizations')

        ldap_options = params
        ldap_options[:encryption] = :simple_tls if ldap_config["ssl"]

        @ldap = Net::LDAP.new(ldap_options)
        @ldap.host = ldap_config["host"]
        @ldap.port = ldap_config["port"]
        @ldap.base = ldap_config["base"]
        @attribute = ldap_config["attribute"]
        @ldap_auth_username_builder = params[:ldap_auth_username_builder]
        
        @group_base = ldap_config["group_base"]
        @required_groups = ldap_config["required_groups"]        
        @required_attributes = ldap_config["require_attribute"]
        
        @ldap.auth ldap_config["admin_user"], ldap_config["admin_password"] if params[:admin] 
                
        @login = params[:login]
        @password = params[:password]
        @new_password = params[:new_password]
      end

      def dn
        DeviseLdapAuthenticatable::Logger.send("LDAP search: #{@attribute}=#{@login}")
        filter = Net::LDAP::Filter.eq(@attribute.to_s, @login.to_s)
        ldap_entry = nil
        @ldap.search(:filter => filter) {|entry| ldap_entry = entry}
        if ldap_entry.nil?
          @ldap_auth_username_builder.call(@attribute,@login,@ldap)
        else
          ldap_entry.dn
        end
      end

      def authenticate!
        @ldap.auth(dn, @password)
        @ldap.bind
      end

      def authenticated?
        authenticate!
      end
      
      def authorized?
        DeviseLdapAuthenticatable::Logger.send("Authorizing user #{dn}")
        authenticated? && in_required_groups? && has_required_attribute?
      end
      
      def change_password!
        update_ldap(:userpassword => Net::LDAP::Password.generate(:sha, @new_password))
      end

      def in_required_groups?     
        return true unless ::Devise.ldap_check_group_membership
        
        ## FIXME set errors here, the ldap.yml isn't set properly.
        return false if @required_groups.nil?   
           
        admin_ldap = LdapConnect.admin
                
        for group in @required_groups
          if group.is_a?(Array)
            group_attribute, group_name = group
          else
            group_attribute = "uniqueMember"
            group_name = group
          end
          admin_ldap.search(:base => group_name, :scope => Net::LDAP::SearchScope_BaseObject) do |entry|
            unless entry[group_attribute].include? dn
              DeviseLdapAuthenticatable::Logger.send("User #{dn} is not in group: #{group_name }")
              return false
            end
          end
        end
        
        return true
      end
      
      def has_required_attribute?
        return true unless ::Devise.ldap_check_attributes
        
        admin_ldap = LdapConnect.admin
        
        user = find_ldap_user(admin_ldap)
                
        @required_attributes.each do |key,val|
          unless user[key].include? val
            DeviseLdapAuthenticatable::Logger.send("User #{dn} did not match attribute #{key}:#{val}")
            return false 
          end
        end
        
        return true
      end
      
      def user_groups
        admin_ldap = LdapConnect.admin

        DeviseLdapAuthenticatable::Logger.send("Getting groups for #{dn}")
        # filter = Net::LDAP::Filter.eq("uniqueMember", dn)
        # this is AD-specific (samaccountname) and should be configurable
        filter = Net::LDAP::Filter.eq('samaccountname', dn.sub(/@.+$/, '')) & Net::LDAP::Filter.eq("objectcategory", "Person")
        # admin_ldap.search(:filter => filter, :base => @ldap.base).collect(&:dn)
        # The above search does not return the groups. You need to look in 'memberof'.
        # This may be AD-specific; I'm not sure.
        if entries = admin_ldap.search(:filter => filter, :base => @ldap.base)
          if entry = entries[0]
            entry[:memberof].collect { |g| g.sub(/.*?CN=(.*?),.*/, '\1') }
          end
        end
      end
      
      private
      
      def self.admin
        ldap = LdapConnect.new(:admin => true).ldap
        
        unless ldap.bind
          DeviseLdapAuthenticatable::Logger.send("Cannot bind to admin LDAP user")
          raise DeviseLdapAuthenticatable::LdapException, "Cannot connect to admin LDAP user"
        end
        
        return ldap
      end
      
      def find_ldap_user(ldap)
        DeviseLdapAuthenticatable::Logger.send("Finding user: #{dn}")
        ldap.search(:base => dn, :scope => Net::LDAP::SearchScope_BaseObject).try(:first)
      end
      
      def update_ldap(ops)
        operations = []
        if ops.is_a? Hash
          ops.each do |key,value|
            operations << [:replace,key,value]
          end
        elsif ops.is_a? Array
          operations = ops
        end

        admin_ldap = LdapConnect.admin
        
        DeviseLdapAuthenticatable::Logger.send("Modifying user #{dn}")
        admin_ldap.modify(:dn => dn, :operations => operations)
      end

    end

  end

end
