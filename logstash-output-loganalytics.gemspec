Gem::Specification.new do |s|
  s.name          = 'logstash-output-loganalytics'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Logstash output plugin for Azure Log Analytics.'
  s.description   = 'Logstash output plugin to send logs to Azure Log Analytics. Uses Log Analytics HTTP Data Collector API under the hood.'
  s.homepage      = 'https://github.com/yesmarket/logstash-output-loganalytics'
  s.authors       = ['Ryan Bartsch']
  s.email         = 'rbartsch@adam.com.au'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "output" }

  # Gem dependencies
  s.add_runtime_dependency "rest-client", "~> 2.0"
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency "logstash-codec-plain"
  s.add_development_dependency "logstash-devutils"
end
