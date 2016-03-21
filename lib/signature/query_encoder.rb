module Signature
  # Query string encoding extracted with thanks from em-http-request
  module QueryEncoder
    class << self
      # URL encodes query parameters
      def encode_params(hash)
        collect_entries_for([], hash) { |v| escape(v) }.join('&')
      end

      # Like encode_param, but doesn't url escape keys or values
      def encode_params_without_escaping(hash)
        collect_entries_for([], hash).join('&')
      end

      private

      def collect_entries_for(prefix, value, entries = [], &block)
        case value
        when Array
          value.each { |v| collect_entries_for(prefix + [nil], v, entries) }
        when Hash
          value = with_normalized_keys value
          value.keys.sort.each do |key|
            collect_entries_for(prefix + [key], value[key], entries)
          end
        else
          entries << entry(prefix, value, &block)
        end
        entries
      end

      def entry(key, value)
        query_key = key.inject('') do |memo, part|
          if part.nil?
            memo << "[]"
          else
            part = if block_given? then yield part else part end
            if memo == ''
              memo << part
            else
              memo << "[#{part}]"
            end
          end
          memo
        end
        value = if block_given? then yield value else value end
        "#{query_key}=#{value}"
      end

      def escape(s)
        if defined?(EscapeUtils)
          EscapeUtils.escape_url(s.to_s)
        else
          s.to_s.gsub(/([^a-zA-Z0-9_.-]+)/n) {
            '%'+$1.unpack('H2'*bytesize($1)).join('%').upcase
          }
        end
      end

      if ''.respond_to?(:bytesize)
        def bytesize(string)
          string.bytesize
        end
      else
        def bytesize(string)
          string.size
        end
      end

      def with_normalized_keys(hash)
        normalized = {}
        hash.each { |key, value| normalized[key.to_s.downcase] = value }
        normalized
      end
    end
  end
end
