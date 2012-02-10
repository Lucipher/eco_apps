module EcoApps
  module Helpers
    def self.included(base)
      base.send(:include, InstanceMethods)
      base.helper_method :url_of,:encode_url
      base.extend SingletonMethods
    end

    module InstanceMethods
      @@encoder = OpenSSL::Cipher::Cipher.new("aes-128-cbc")
      def url_of(app_name, url_key, options={})
        app = MasterService.app(app_name)
        # root = EcoApps::Util.env_value(YAML.load(app.url.to_s) )
        root = request.protocol +  request.host + "/" + app_name.to_s

        api = app.api
        api = YAML.load(api) if api.is_a?(String)
        begin
          path = api["url"][url_key.to_s] || ""
          options.each{|k,v| path.gsub!(":#{k}", v.to_s)}

          URI.parse(root).add_path(path).add_query(options[:params]).to_s
        rescue Exception => e
          raise "#{url_key} of #{app_name} seems not configured correctly in #{app_name}'s config/app_config.yml"
        end
      end

      def full_path_of(path, app = nil)
        return nil if path.blank?
        return path if path =~ /^(http|https):\/\//
        path = "/" + (path.split("/")-[""]).join("/")

        if Rails.env.production? and ( request.subdomains.first =~ /^www/ or request.subdomains.first =~ /^ellis/ or request.subdomains.first =~ /^tc/ or request.subdomains.first =~ /^teachcast/)
          prefix = "/#{(app||EcoApps.current.name)}"
        else
          prefix = (app.blank? ? "" : "#{EcoApps.base_url}/#{app}")
        end
        prefix + path
      end

      def authenticate_ip_address(extra = nil)
        legal_ip = EcoApps.legal_ip
        legal_ip += EcoApps::Util.convert_ip(extra) unless extra.blank?
        legal_ip.each do |ip|
          return if ip.matches?(request.remote_ip)
        end
        respond_to do |format|
          format.html{ render :text => "Access Denied!", :status => :forbidden }
          format.xml{ render :xml => {:info => "Access Denied!"}.to_xml, :status => :forbidden}
        end
      end
      
      def idp_password
        Digest::SHA1.hexdigest("ay8nW4t_idapted")
      end
      
      # Add encrypted key to url to protect it from forgery
      #   link_to "view", encode_url(article_path(1))
      def encode_url(url)
        key = encode("#{extract_ids(url)}#{idp_password}", true)
        url + (url.include?("?") ? "&" : "?") + "key=#{key}"
      end
      
      def encrypt(data)
        Digest::SHA1.hexdigest(data)
      end

      def encode(data, escape=false)
        c = @@encoder
        c.encrypt
        c.key = idp_password
        e = c.update(data)
        e << c.final
        v = Base64.encode64(e)
        escape ? Url.escape(v) : v
      end

      def decode(encoded_data, unescape=false)
        c = @@encoder
        c.decrypt
        c.key = idp_password
        d = c.update(Base64.decode64(unescape ? URI.unescape(encoded_data) : encoded_data))
        d << c.final
        d
      end

      def extract_ids(url_string)
        raw_url = url_string.gsub(/key=[^&]+/, "")
        raw_url.gsub(/[^\d]+/, "")
      end
      

      
      protected
      def authenticate_url
        key = "#{extract_ids(request.url)}#{idp_password}"
        render :text => I18n.t("common.illegal_request") unless key == decode(params[:key], true)
      end
      
    end

    module SingletonMethods
      def ip_limited_access(options = {})
        extra = options.delete(:extra)
        before_filter(options){|c| c.authenticate_ip_address(extra)} if Rails.env.production?
      end
      
      # Works together with encode_url, protecting action from forgery.
      #   ArticlesController < ActionController::Base
      #     protect_action :show
      #     def show
      #       ...
      #     end
      #   end
      def protect_action(*actions)
        before_filter :authenticate_url, :only => actions
      end
    end


    class Url
      class << self
        def escape(url)
          URI.escape(url, Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
        end
      end
    end
  end
end

