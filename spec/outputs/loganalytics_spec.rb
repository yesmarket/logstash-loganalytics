# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/outputs/loganalytics"
require "logstash/codecs/plain"
require "logstash/event"

describe LogStash::Outputs::Loganalytics do
  let(:client_id) { 'test' }
  let(:client_secret) { 'test' }
  let(:table) { 'logstashplugintest' }

  let(:cfg) {
    { 
      "client_id" => client_id, 
      "client_secret" => client_secret,
      "table" => table
    }
  }

  let(:output) { LogStash::Outputs::Loganalytics.new(cfg) }

  before do
    output.register
  end

  describe "#receive" do
    it "Should successfully send the event to log analytics" do
      log = {
        :logid => "628cc9db-0aec-4423-83d2-c78c11bd9b94",
        :message => "this is a test",
        :level => "info"
      }

      event = LogStash::Event.new(log) 
      expect {output.receive(event)}.to_not raise_error
    end

  end
end
