# frozen_string_literal: true

require 'spec_helper'
require 'openssl'

RSpec.describe 'SSL Configuration' do
  describe 'MCPClient.http_config' do
    it 'includes ssl option when provided' do
      ssl_options = { verify: false }
      config = MCPClient.http_config(base_url: 'https://example.com', ssl: ssl_options)

      expect(config[:ssl]).to eq(ssl_options)
    end

    it 'omits ssl key when nil' do
      config = MCPClient.http_config(base_url: 'https://example.com')

      expect(config).not_to have_key(:ssl)
    end

    it 'accepts cert_store option' do
      cert_store = OpenSSL::X509::Store.new
      ssl_options = { cert_store: cert_store, verify: true }
      config = MCPClient.http_config(base_url: 'https://example.com', ssl: ssl_options)

      expect(config[:ssl][:cert_store]).to eq(cert_store)
      expect(config[:ssl][:verify]).to be true
    end
  end

  describe 'MCPClient.streamable_http_config' do
    it 'includes ssl option when provided' do
      ssl_options = { verify: false }
      config = MCPClient.streamable_http_config(base_url: 'https://example.com', ssl: ssl_options)

      expect(config[:ssl]).to eq(ssl_options)
    end

    it 'omits ssl key when nil' do
      config = MCPClient.streamable_http_config(base_url: 'https://example.com')

      expect(config).not_to have_key(:ssl)
    end

    it 'accepts cert_store option' do
      cert_store = OpenSSL::X509::Store.new
      ssl_options = { cert_store: cert_store, verify: true }
      config = MCPClient.streamable_http_config(base_url: 'https://example.com', ssl: ssl_options)

      expect(config[:ssl][:cert_store]).to eq(cert_store)
      expect(config[:ssl][:verify]).to be true
    end
  end

  describe 'MCPClient::HttpTransportBase#build_ssl_config' do
    let(:test_class) do
      Class.new do
        include MCPClient::HttpTransportBase

        attr_accessor :ssl_options, :base_url, :max_retries, :retry_backoff, :read_timeout, :logger, :mutex, :headers

        def initialize(ssl_options: nil)
          @ssl_options = ssl_options
          @base_url = 'https://example.com'
          @max_retries = 3
          @retry_backoff = 1
          @read_timeout = 30
          @logger = Logger.new(nil)
          @mutex = Monitor.new
          @headers = {}
          @request_id = 0
        end

        # Expose private method for testing
        def test_build_ssl_config
          build_ssl_config
        end

        # Stub abstract methods
        def parse_response(_response)
          {}
        end

        def ensure_connected; end
      end
    end

    context 'with default SSL options (nil)' do
      it 'sets TLS 1.2 as minimum version' do
        transport = test_class.new
        config = transport.test_build_ssl_config

        expect(config[:min_version]).to eq(OpenSSL::SSL::TLS1_2_VERSION)
      end

      it 'sets TLS 1.3 as maximum version when available' do
        skip 'TLS 1.3 not available' unless OpenSSL::SSL.const_defined?(:TLS1_3_VERSION)

        transport = test_class.new
        config = transport.test_build_ssl_config

        expect(config[:max_version]).to eq(OpenSSL::SSL::TLS1_3_VERSION)
      end
    end

    context 'with custom SSL options' do
      it 'merges user-provided SSL options' do
        custom_options = { verify: false }
        transport = test_class.new(ssl_options: custom_options)
        config = transport.test_build_ssl_config

        expect(config[:verify]).to be false
        # Still has default TLS version
        expect(config[:min_version]).to eq(OpenSSL::SSL::TLS1_2_VERSION)
      end

      it 'allows user to override TLS version constraints' do
        custom_options = { min_version: OpenSSL::SSL::TLS1_3_VERSION }
        transport = test_class.new(ssl_options: custom_options)
        config = transport.test_build_ssl_config

        expect(config[:min_version]).to eq(OpenSSL::SSL::TLS1_3_VERSION)
      end

      it 'passes through cert_store option' do
        cert_store = OpenSSL::X509::Store.new
        custom_options = { cert_store: cert_store }
        transport = test_class.new(ssl_options: custom_options)
        config = transport.test_build_ssl_config

        expect(config[:cert_store]).to eq(cert_store)
      end

      it 'passes through ca_file option' do
        custom_options = { ca_file: '/path/to/ca.pem' }
        transport = test_class.new(ssl_options: custom_options)
        config = transport.test_build_ssl_config

        expect(config[:ca_file]).to eq('/path/to/ca.pem')
      end

      it 'passes through ca_path option' do
        custom_options = { ca_path: '/path/to/certs' }
        transport = test_class.new(ssl_options: custom_options)
        config = transport.test_build_ssl_config

        expect(config[:ca_path]).to eq('/path/to/certs')
      end

      it 'passes through client_cert option' do
        custom_options = { client_cert: 'cert_data' }
        transport = test_class.new(ssl_options: custom_options)
        config = transport.test_build_ssl_config

        expect(config[:client_cert]).to eq('cert_data')
      end

      it 'passes through client_key option' do
        custom_options = { client_key: 'key_data' }
        transport = test_class.new(ssl_options: custom_options)
        config = transport.test_build_ssl_config

        expect(config[:client_key]).to eq('key_data')
      end

      it 'ignores non-hash ssl_options' do
        transport = test_class.new(ssl_options: 'invalid')
        config = transport.test_build_ssl_config

        # Should only have default options
        expect(config.keys).to include(:min_version)
        expect(config).not_to have_key(:verify)
      end
    end
  end

  describe 'MCPClient::HttpTransportBase#create_http_connection' do
    let(:test_class) do
      Class.new do
        include MCPClient::HttpTransportBase

        attr_accessor :ssl_options, :base_url, :max_retries, :retry_backoff, :read_timeout, :logger, :mutex, :headers

        def initialize(ssl_options: nil)
          @ssl_options = ssl_options
          @base_url = 'https://example.com'
          @max_retries = 3
          @retry_backoff = 1
          @read_timeout = 30
          @logger = Logger.new(nil)
          @mutex = Monitor.new
          @headers = {}
          @request_id = 0
        end

        # Expose private method for testing
        def test_create_http_connection
          create_http_connection
        end

        # Stub abstract methods
        def parse_response(_response)
          {}
        end

        def ensure_connected; end
      end
    end

    it 'creates Faraday connection with SSL config' do
      transport = test_class.new(ssl_options: { verify: false })

      # Capture what's passed to Faraday.new
      ssl_config_passed = nil
      allow(Faraday).to receive(:new) do |options, &_block|
        ssl_config_passed = options[:ssl]
        instance_double('Faraday::Connection')
      end

      transport.test_create_http_connection

      expect(ssl_config_passed).to be_a(Hash)
      expect(ssl_config_passed[:verify]).to be false
      expect(ssl_config_passed[:min_version]).to eq(OpenSSL::SSL::TLS1_2_VERSION)
    end

    it 'does not pass SSL config when no options provided' do
      transport = test_class.new

      options_passed = nil
      allow(Faraday).to receive(:new) do |options, &_block|
        options_passed = options
        instance_double('Faraday::Connection')
      end

      transport.test_create_http_connection

      expect(options_passed).not_to have_key(:ssl)
    end
  end

  describe 'MCPClient::ServerHTTP' do
    it 'stores ssl_options from initialization' do
      ssl_options = { verify: false }

      server = MCPClient::ServerHTTP.new(
        base_url: 'https://example.com',
        ssl: ssl_options
      )

      expect(server.instance_variable_get(:@ssl_options)).to eq(ssl_options)
    end

    it 'defaults ssl_options to nil' do
      server = MCPClient::ServerHTTP.new(base_url: 'https://example.com')

      expect(server.instance_variable_get(:@ssl_options)).to be_nil
    end
  end

  describe 'MCPClient::ServerStreamableHTTP' do
    it 'stores ssl_options from initialization' do
      ssl_options = { verify: false }

      server = MCPClient::ServerStreamableHTTP.new(
        base_url: 'https://example.com',
        ssl: ssl_options
      )

      expect(server.instance_variable_get(:@ssl_options)).to eq(ssl_options)
    end

    it 'defaults ssl_options to nil' do
      server = MCPClient::ServerStreamableHTTP.new(base_url: 'https://example.com')

      expect(server.instance_variable_get(:@ssl_options)).to be_nil
    end
  end
end
