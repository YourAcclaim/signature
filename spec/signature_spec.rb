require File.expand_path('../spec_helper', __FILE__)

describe Signature do
  before :each do
    allow(Time).to receive(:now).and_return(1234)

    @token = Signature::Token.new('key', 'secret')

    @request = Signature::Request.new('POST', '/some/path', {
      "query" => "params",
      "go" => "here"
    })
  end

  describe "generating signatures" do
    before :each do
      @signature = "3b237953a5ba6619875cbb2a2d43e8da9ef5824e8a2c689f6284ac85bc1ea0db"
    end

    it "should generate signature correctly" do
      @request.sign(@token)
      string = @request.send(:string_to_sign)
      expect(string).to eq("POST\n/some/path\nauth_key=key&auth_timestamp=1234&auth_version=1.0&go=here&query=params")

      digest = OpenSSL::Digest::SHA256.new
      signature = OpenSSL::HMAC.hexdigest(digest, @token.secret, string)
      expect(signature).to eq(@signature)
    end

    it "should make auth_hash available after request is signed" do
      @request.query_hash = {
        "query" => "params"
      }
      expect { @request.auth_hash }.to raise_error('Request not signed')

      @request.sign(@token)
      expect(@request.auth_hash).to eq({
        :auth_signature => "da078fcedd72941b6c873caa40d0d6b2000ebfc700cee802b128dd20f72e74e9",
        :auth_version => "1.0",
        :auth_key => "key",
        :auth_timestamp => '1234'
      })
    end

    it "should cope with symbol keys" do
      @request.query_hash = {
        :query => "params",
        :go => "here"
      }
      expect(@request.sign(@token)[:auth_signature]).to eq(@signature)
    end

    it "should cope with upcase keys (keys are lowercased before signing)" do
      @request.query_hash = {
        "Query" => "params",
        "GO" => "here"
      }
      expect(@request.sign(@token)[:auth_signature]).to eq(@signature)
    end

    it "should generate correct string when query hash contains array" do
      @request.query_hash = {
        "things" => ["thing1", "thing2"]
      }
      expect(@request.send(:string_to_sign)).to eq("POST\n/some/path\nthings[]=thing1&things[]=thing2")
    end

    it "should generate correct string when query hash contains nested elements" do
      @request.query_hash = {
        "things" => [{ "thing_1" => "value1" }, { "thing_2" => "value2" }]
      }
      expect(@request.send(:string_to_sign)).to eq(
        "POST\n/some/path\nthings[][thing_1]=value1&things[][thing_2]=value2"
      )
    end

    it "should generate correct string when query hash contains nested arrays" do
      @request.query_hash = {
        "things" => [{ "thing_1" => [["v1", "v1"]] }, { "thing_2" => [["v2", "v2"]] }]
      }
      expect(@request.send(:string_to_sign)).to eq(
        "POST\n/some/path\nthings[][thing_1][][]=v1&things[][thing_1][][]=v1"\
        "&things[][thing_2][][]=v2&things[][thing_2][][]=v2"
      )
    end

    # This may well change in auth version 2
    it "should not escape keys or values in the query string" do
      @request.query_hash = {
        "key;" => "value@"
      }
      expect(@request.send(:string_to_sign)).to eq("POST\n/some/path\nkey;=value@")
    end

    it "should cope with requests where the value is nil (antiregression)" do
      @request.query_hash = {
        "key" => nil
      }
      expect(@request.send(:string_to_sign)).to eq("POST\n/some/path\nkey=")
    end

    it "should use the path to generate signature" do
      @request.path = '/some/other/path'
      expect(@request.sign(@token)[:auth_signature]).not_to eq(@signature)
    end

    it "should use the query string keys to generate signature" do
      @request.query_hash = {
        "other" => "query"
      }
      expect(@request.sign(@token)[:auth_signature]).not_to eq(@signature)
    end

    it "should use the query string values to generate signature" do
      @request.query_hash = {
        "key" => "notfoo",
        "other" => 'bar'
      }
      expect(@request.sign(@token)[:signature]).not_to eq(@signature)
    end
  end

  describe "verification" do
    before :each do
      @request.sign(@token)
      @params = @request.signed_params
    end

    it "should verify requests" do
      request = Signature::Request.new('POST', '/some/path', @params)
      expect(request.authenticate_by_token(@token)).to eq(true)
    end

    it "should raise error if signature is not correct" do
      @params[:auth_signature] =  'asdf'
      request = Signature::Request.new('POST', '/some/path', @params)
      expect {
        request.authenticate_by_token!(@token)
      }.to raise_error('Invalid signature: you should have sent HmacSHA256Hex("POST\n/some/path\nauth_key=key&auth_timestamp=1234&auth_version=1.0&go=here&query=params", your_secret_key), but you sent "asdf"')
    end

    it "should raise error if timestamp not available" do
      @params.delete(:auth_timestamp)
      request = Signature::Request.new('POST', '/some/path', @params)
      expect {
        request.authenticate_by_token!(@token)
      }.to raise_error('Timestamp required')
    end

    it "should raise error if timestamp has expired (default of 600s)" do
      request = Signature::Request.new('POST', '/some/path', @params)
      allow(Time).to receive(:now).and_return(Time.at(1234 + 599))
      expect(request.authenticate_by_token!(@token)).to eq(true)
      allow(Time).to receive(:now).and_return(Time.at(1234 - 599))
      expect(request.authenticate_by_token!(@token)).to eq(true)
      allow(Time).to receive(:now).and_return(Time.at(1234 + 600))
      expect {
        request.authenticate_by_token!(@token)
      }.to raise_error("Timestamp expired: Given timestamp (1970-01-01T00:20:34Z) not within 600s of server time (1970-01-01T00:30:34Z)")
      allow(Time).to receive(:now).and_return(Time.at(1234 - 600))
      expect {
        request.authenticate_by_token!(@token)
      }.to raise_error("Timestamp expired: Given timestamp (1970-01-01T00:20:34Z) not within 600s of server time (1970-01-01T00:10:34Z)")
    end

    it "should be possible to customize the timeout grace period" do
      grace = 10
      request = Signature::Request.new('POST', '/some/path', @params)
      allow(Time).to receive(:now).and_return(Time.at(1234 + grace - 1))
      expect(request.authenticate_by_token!(@token, grace)).to eq(true)
      allow(Time).to receive(:now).and_return(Time.at(1234 + grace))
      expect {
        request.authenticate_by_token!(@token, grace)
      }.to raise_error("Timestamp expired: Given timestamp (1970-01-01T00:20:34Z) not within 10s of server time (1970-01-01T00:20:44Z)")
    end

    it "should be possible to skip timestamp check by passing nil" do
      request = Signature::Request.new('POST', '/some/path', @params)
      allow(Time).to receive(:now).and_return(Time.at(1234 + 1000))
      expect(request.authenticate_by_token!(@token, nil)).to eq(true)
    end

    it "should check that auth_version is supplied" do
      @params.delete(:auth_version)
      request = Signature::Request.new('POST', '/some/path', @params)
      expect {
        request.authenticate_by_token!(@token)
      }.to raise_error('Version required')
    end

    it "should check that auth_version equals 1.0" do
      @params[:auth_version] = '1.1'
      request = Signature::Request.new('POST', '/some/path', @params)
      expect {
        request.authenticate_by_token!(@token)
      }.to raise_error('Version not supported')
    end

    it "should validate that the provided token has a non-empty secret" do
      token = Signature::Token.new('key', '')
      request = Signature::Request.new('POST', '/some/path', @params)

      expect {
        request.authenticate_by_token!(token)
      }.to raise_error('Provided token is missing secret')
    end

    describe "when used with optional block" do
      it "should optionally take a block which yields the signature" do
        request = Signature::Request.new('POST', '/some/path', @params)
        expect(request.authenticate do |key|
          expect(key).to eq(@token.key)
          @token
        end).to eq(@token)
      end

      it "should raise error if no auth_key supplied to request" do
        @params.delete(:auth_key)
        request = Signature::Request.new('POST', '/some/path', @params)
        expect {
          request.authenticate { |key| nil }
        }.to raise_error('Missing parameter: auth_key')
      end

      it "should raise error if block returns nil (i.e. key doesn't exist)" do
        request = Signature::Request.new('POST', '/some/path', @params)
        expect {
          request.authenticate { |key| nil }
        }.to raise_error('Unknown auth_key')
      end

      it "should raise unless block given" do
        request = Signature::Request.new('POST', '/some/path', @params)
        expect {
          request.authenticate
        }.to raise_error(ArgumentError, "Block required")
      end
    end

    describe "authenticate_async" do
      include EM::SpecHelper
      default_timeout 1

      it "returns a deferrable which succeeds if authentication passes" do
        request = Signature::Request.new('POST', '/some/path', @params)
        em {
          df = EM::DefaultDeferrable.new

          request_df = request.authenticate_async do |key|
            df
          end

          df.succeed(@token)

          request_df.callback { |token|
            expect(token).to eq(@token)
            done
          }
        }
      end

      it "returns a deferrable which fails if block df fails" do
        request = Signature::Request.new('POST', '/some/path', @params)
        em {
          df = EM::DefaultDeferrable.new

          request_df = request.authenticate_async do |key|
            df
          end

          df.fail()

          request_df.errback { |e|
            expect(e.class).to eq(Signature::AuthenticationError)
            expect(e.message).to eq('Unknown auth_key')
            done
          }
        }
      end

      it "returns a deferrable which fails if request does not validate" do
        request = Signature::Request.new('POST', '/some/path', @params)
        em {
          df = EM::DefaultDeferrable.new

          request_df = request.authenticate_async do |key|
            df
          end

          token = Signature::Token.new('key', 'wrong_secret')
          df.succeed(token)

          request_df.errback { |e|
            expect(e.class).to eq(Signature::AuthenticationError)
            expect(e.message).to match(/Invalid signature/)
            done
          }
        }
      end
    end
  end
end
