# frozen_string_literal: true

require 'rex/socket'

class ModuleDatastore
  def initialize(store = {}, mod)
    @store = store.clone
    @options = {}
    # Only used within the module datastore, and not the 'global' one
    # @_module = mod
  end

  def []=(k, v)
    store[find_alias_name(k)] = v
  end

  def [](k)
    store[find_alias_name(k)]
  end

  def import_options(options, imported_by = nil, overwrite = false)
    options.each do |name, opt|
      if self[name].nil?
        import_option(name, opt.default, true, imported_by, opt)
      end
    end
  end

  def import_option(key, val, imported = true, imported_by = nil, option = nil)
    self[key] = val
    @options[key] = option
  end

  def merge(other)
    ModuleDatastore.new(store.merge(other), @mod)
  end

  private

  attr :store

  def find_alias_name(name)
    @options.find { |option| option.alias == name }&.name || name
  end
end

class Option
  attr :name, :default, :description, :alias

  def initialize(options)
    @name = options[:name]
    @default = options[:default]
    @description = options[:description]
    @alias = options[:alias]
  end
end

class RHost < Option
  def initialize(options = {})
    super(
      {
        # NOTE: Actually registered as RHOSTS within framework with an alias set up
        name: 'RHOSTS',
        default: nil,
        description: 'RHOSTS - examples: 10.10.10.10, http://x.x.x.x/foo/bar, cidr:/24:http://10.10.0.0:8080',
        alias: 'RHOST'
      }.merge(options)
    )
  end

  def validate; end
end

class RPort < Option
  def initialize(options)
    super(
      {
        name: 'RPORT',
        default: nil,
        description: 'The remote port to target'
      }.merge(options)
    )
  end

  def validate; end
end

class OptionContainer
  def initialize
    @options = {}
  end

  def add(option)
    options[option.name] = option
  end

  def each(&block)
    options.values.each(&block)
  end

  def [](name)
    options.each do |(_name, option)|
      return option if option.name == name
    end

    nil
  end

  private

  attr :options
end

class MockModule

  def initialize
    @datastore = ModuleDatastore.new(self)
    @options = OptionContainer.new

    register_options(
      [
        RHost.new,
        RPort.new(default: 8080)
      ]
    )
  end

  def register_options(options)
    options.each do |option|
      self.options.add(option)
    end
  end

  def get_targets
    TargetEnumerator.new(self).get_targets
  end

  def run
    puts "Running with current #{datastore['RHOST']}"
  end

  def replicant
    mod = self.clone
    mod.datastore = self.datastore.clone
    mod
  end

  attr :datastore, :options

  attr_writer :datastore
  attr_writer :options
end

# TODO: How would this work with credentials, targets, etc. In a memory safe/repeatable way?
class TargetEnumerator
  def initialize(mod)
    @mod = mod
  end

  def get_targets
    Enumerator.new do |result|
      # TODO: Would have to implement priorities of rport, etc.
      if @mod.options['RHOSTS']
        targets = @mod.datastore['RHOSTS']
        targets.split(' ').each do |target|
          target_datastore = @mod.datastore.merge(
            'RHOST' => target,
            'RPORT' => @mod.datastore['RPORT'] || @mod.options['RPORT'].default
          )
          result << target_datastore
        end
      end
    end
  end

  private

  def parse_rtargets(rtargets)
    items = rtargets.split(' ')
    items.each do |item|
      if item.start_with?('http:') || item.start_with('https:')
        URI
      end

    end
  end

  def parse_http_uri(value)
    return unless value

    uri = get_uri(value)
    return unless uri

    option_hash = {}
    # Blank this out since we don't know if this new value will have a `VHOST` to ensure we remove the old value
    option_hash['VHOST'] = nil

    option_hash['RHOSTS'] = uri.hostname
    option_hash['RPORT'] = uri.port
    option_hash['SSL'] = %w[ssl https].include?(uri.scheme)

    # Both `TARGETURI` and `URI` are used as datastore options to denote the path on a uri
    option_hash['TARGETURI'] = uri.path.present? ? uri.path : '/'
    option_hash['URI'] = option_hash['TARGETURI']

    if uri.scheme && %(http https).include?(uri.scheme)
      option_hash['VHOST'] = uri.hostname unless Rex::Socket.is_ip_addr?(uri.hostname)
      option_hash['HttpUsername'] = uri.user.to_s
      option_hash['HttpPassword'] = uri.password.to_s
    end

    option_hash
  end
end

class TomcatModule < MockModule
  def initialize
    super

    register_options(
      [
        RPort.new(default: 8080)
      ]
    )
  end
end

class Job
  attr_reader :name, :datastore
end

# Could be something like redis in the future
class ModuleSchedulerDatastore
  def initialize
    # @store = {}
    @jobs = []
  end

  def any?
    @jobs.any?
  end

  def push(job)
    @jobs << job
  end

  def pop
    @jobs.pop
  end
end

# runs treads efficiently
class ModuleScheduler
  def initialize
    @datastore = ModuleSchedulerDatastore.new
    @workers = []
  end

  def perform_async(mods)
    mods.each do |mod|
      mod.get_targets.each do |datastore|
        @datastore.push(
          {
            mod: mod,
            datastore: datastore
          }
        )
      end
    end
  end

  def get_results(uuid)
    @datastore.any? ? :not_done : :done
  end

  def register_worker(worker_class)
    worker = worker_class.new(@datastore)
    @workers << worker
    worker.run

    true
  end

  def stop
    @workers.each(&:stop)
  end
end

class ModuleWorker
  def initialize(datastore)
    @datastore = datastore
  end

  def stop
    return unless @thread

    @thread.kill
    @thread.join
  end

  def run
    @thread = Thread.new do
      loop do
        job = datastore.pop
        unless job
          sleep 1
          next
        end

        mod = job[:mod].replicant
        mod.datastore = job[:datastore]
        mod.run
        sleep 1
      end
    end
  end

  private

  attr :datastore
end

module_scheduler = ModuleScheduler.new
tomcat_module = TomcatModule.new
tomcat_module.datastore['RHOSTS'] = (0..5).map { |x| "10.10.10.#{x}" }.join(' ')
# tomcat_module.datastore['RHOSTS'] = "http://www.google.com"

# module_scheduler.batch do |batch|
#   batch.jobs do
#
#   end
# end

job_id = module_scheduler.perform_async(
  [
    tomcat_module
  ]
)

# TODO: Doesn't work if you have out of band workers
module_scheduler.register_worker(ModuleWorker)
module_scheduler.register_worker(ModuleWorker)
module_scheduler.register_worker(ModuleWorker)
module_scheduler.register_worker(ModuleWorker)
module_scheduler.register_worker(ModuleWorker)
module_scheduler.register_worker(ModuleWorker)

loop do
  results = module_scheduler.get_results(job_id)
  if results == :done
    puts 'done!'
    break
  else
    # sleep 1
  end
end

module_scheduler.stop

def display_module(mod)
  puts "module: #{mod.class}"
  mod.options.each do |option|
    puts "#{option.name}=#{mod.datastore[option.name]}"
  end
end

display_module(tomcat_module)
