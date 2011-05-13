module EcoApps

  mattr_accessor :current

  class << self
    
    def base_url
      url = load_from_conf(:base_url)
      url = if url.is_a?(Hash)
        url[Rails.env]
      else
        url
      end
      
      if url.blank?
        raise "please set #{Rails.env} env base_url in app_config.yml"
      else
        return url
      end
    end
    
    def validate_master_app_url!
      url = self.master_app_url
      raise 'Please set master_app_url in GEM_DIR/eco_apps/lib/platform_config.yml or APP_ROOT/config/app_config.yml!' if url.blank?
      raise 'master_app_url must begin with http:// or https://' if not url =~ Regexp.new("(http|https)://")
    end

    def validate_legal_ip!
      raise "legal_ip is not identified!" if load_from_conf(:legal_ip).blank?
    end

    def master_app_url
      url = load_from_conf(:master_app_url)
      url = if url.is_a?(Hash)
        url[Rails.env]
      else
        url
      end
      
      if url.blank?
        raise "please set #{Rails.env} env master_app_url in app_config.yml"
      else
        return url
      end
    end

    def legal_ip
      EcoApps::Util.convert_ip(load_from_conf(:legal_ip))
    end

    def in_master_app?
      self.master_app == self.current.name
    end

    def config_file
      File.join(File.dirname(__FILE__), "../platform_config.yml")
    end

    def method_missing(method_name, *args)
      (args.blank? and method_name.to_s =~ /^[a-z0-9_]+$/) ? load_from_conf(method_name) : super
    end

    private

    def load_from_conf(method_name)
      EcoApps::Util.env_value(current.send(method_name) || YAML.load(config_file)[method_name.to_s])
    end

  end

  class App
    attr_reader :config

    def initialize(options = {})
      @config = options
    end

    def method_missing(method_name, *args)
      m = method_name.to_s
      api = @config['api'].is_a?(String) ? YAML.load(@config['api']) : @config['api']
      if m != "url" and @config["api"].present? and api.keys.include?(m)
        v = @config["api"][m]
      else
        v = @config[m]
      end
      EcoApps::Util.env_value v
    end

    def eco_apps_config
      @config.clone.extract!("name", "url", "api", "database")
    end

    class << self
      def config_file
        Rails.root.join("config/app_config.yml")
      end

      def cache_key
        "cached_config"
      end
      
      def fetch(app_name)
        if cache = EcoApps::App.read_cache(app_name)
          cache
        else
          cache = yield
          EcoApps::App.write_cache(app_name, cache.clone.to_hash)
          cache
        end
      end

      def read_cache(app_name)
        cache = YAML.load_file(self.config_file)[cache_key].try("[]", app_name.to_s)
        cache.blank? ? nil : cache.merge!("name" => app_name)
      end

      def write_cache(app_name, options)
        options.delete("name")
        edit_config_file do |config|
          config[cache_key] ||= {}
          config[cache_key][app_name] = options.merge!(config[cache_key][app_name]||{})
        end
      end

      def delete_cache(app_name)
        edit_config_file do |config|
          config[cache_key].delete(app_name) if config[cache_key].try("[]", app_name).present?
        end
      end

      private
      def edit_config_file(&block)
        config = YAML.load_file(self.config_file)
        block.call(config)
        File.open(self.config_file, 'w') {|f| f.write(config.to_yaml)}
      end
    end
  end

end
