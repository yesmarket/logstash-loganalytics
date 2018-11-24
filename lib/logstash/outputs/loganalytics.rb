# encoding: utf-8
require "logstash/outputs/base"
require "logstash/namespace"
require 'rest-client'
require 'json'
require 'openssl'
require 'base64'
require 'time'

class LogStash::Outputs::Loganalytics < LogStash::Outputs::Base
  config_name "loganalytics"

  # Your Operations Management Suite workspace ID
  config :customer_id, :validate => :string, :required => true

  # The primary or the secondary Connected Sources client authentication key
  config :shared_key, :validate => :string, :required => true

  # The name of the event type that is being submitted to Log Analytics. This must be only alpha characters.
  config :log_type, :validate => :string, :required => true

  # The name of the time generated field. Be carefule that the value of field should strictly follow the ISO 8601 format (YYYY-MM-DDThh:mm:ssZ)
  config :time_generated_field, :validate => :string, :default => '', :required => false

  public
  def register
  	raise ArgumentError, 'log_type must be only alpha characters and less than 100 characters' unless @log_type.match(/^[a-zA-Z]{1,100}$/)
    @uri = "https://#{@customer_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
  end

  def receive(event)
    begin
      body =  event.to_json
      date = Time.now.httpdate
      string_to_hash = "POST\n#{body.bytesize}\napplication/json\nx-ms-date:#{date}\n/api/logs"
      hashed_string = Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), Base64.decode64(@shared_key), string_to_hash.encode('utf-8')))
      headers = {}
      headers['Content-Type'] = 'application/json'
      headers['Authorization'] = "SharedKey #{@customer_id}:#{hashed_string}"
      headers['Log-Type'] = @log_type
      headers['x-ms-date'] = date
      unless @time_generated_field.empty?
        headers['time-generated-field'] = @time_generated_field
      end
      response = RestClient.post(@uri, body, headers)
      unless response.code == 200
        $logger.error("DataCollector API request failure: error code: #{response.code}, data=>#{event}")
      end
    rescue Exception => ex
      $logger.error("Exception occured in posting to DataCollector API: '#{ex}', data=>#{event}")
    end
  end

end
