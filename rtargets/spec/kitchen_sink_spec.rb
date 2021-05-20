require 'spec_helper'
require 'tempfile'
require_relative '../main'

RSpec.describe 'the kitchen sink' do
  describe 'RHOST calculation' do
    let(:mod) { TomcatModule.new }

    before(:each) do
      @temp_files = []
      allow(mod).to receive(:datastore).and_return(datastore)
    end

    def create_tempfile(content)
      file = Tempfile.new
      @temp_files << file
      file.write(content)
      file.flush

      file.path
    end

    after do
      @temp_files.each(&:unlink)
    end

    context 'when there is a single RHOST' do
      let(:datastore) do
        store = ModuleDatastore.new(
          {
            'RHOSTS' => '127.0.0.1'
          },
          mod
        )
        store.import_options(mod.options)
        store
      end

      it 'calculates the required targets' do
        expected = [
          { "RHOSTS" => "127.0.0.1", "RPORT" => 8080 }
        ]
        expect(mod.get_targets.to_a.map(&:to_h)).to eq(expected)
      end
    end

    context 'when single hosts are separated by spaces' do
      let(:datastore) do
        store = ModuleDatastore.new(
          {
            'RHOSTS' => '127.0.0.1 127.0.0.2 127.0.0.3'
          },
          mod
        )
        store.import_options(mod.options)
        store
      end

      it 'calculates the required targets' do
        expected = [
          { "RHOSTS" => "127.0.0.1", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.2", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.3", "RPORT" => 8080 },
        ]
        expect(mod.get_targets.to_a.map(&:to_h)).to eq(expected)
      end
    end

    context 'when there are multiple RHOSTS' do
      let(:datastore) do
        store = ModuleDatastore.new(
          {
            'RHOSTS' => '127.0.0.0/30'
          },
          mod
        )
        store.import_options(mod.options)
        store
      end

      it 'calculates the required targets' do
        expected = [
          { "RHOSTS" => "127.0.0.0", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.1", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.2", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.3", "RPORT" => 8080 },
        ]
        expect(mod.get_targets.to_a.map(&:to_h)).to eq(expected)
      end
    end

    context 'when there are multiple RHOSTS' do
      let(:datastore) do
        store = ModuleDatastore.new(
          {
            'RHOSTS' => '127.0.0.0/30'
          },
          mod
        )
        store.import_options(mod.options)
        store
      end

      before do
        allow(File)
      end

      it 'calculates the required targets' do
        expected = [
          { "RHOSTS" => "127.0.0.0", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.1", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.2", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.3", "RPORT" => 8080 },
        ]
        expect(mod.get_targets.to_a.map(&:to_h)).to eq(expected)
      end
    end

    context 'when there is a file value' do
      let(:datastore) do
        temp_file = create_tempfile("127.0.0.0\n127.0.0.1")
        store = ModuleDatastore.new(
          {
            'RHOSTS' => "file:#{temp_file}"
          },
          mod
        )
        store.import_options(mod.options)
        store
      end

      it 'calculates the required targets' do
        expected = [
          { "RHOSTS" => "127.0.0.0", "RPORT" => 8080 },
          { "RHOSTS" => "127.0.0.1", "RPORT" => 8080 },
        ]
        expect(mod.get_targets.to_a.map(&:to_h)).to eq(expected)
      end
    end

    context 'when there is an http value' do
      let(:datastore) do
        store = ModuleDatastore.new(
          {
            'RHOSTS' => "http://www.example.com/foo"
          },
          mod
        )
        store.import_options(mod.options)
        store
      end

      it 'calculates the required targets' do
        expected = [
          {"HttpPassword"=>"", "HttpUsername"=>"", "RHOSTS"=>"www.example.com", "RPORT"=>80, "SSL"=>false, "TARGETURI"=>"/foo", "URI"=>"/foo", "VHOST"=>"www.example.com"}
        ]
        expect(mod.get_targets.to_a.map(&:to_h)).to eq(expected)
      end
    end

    context 'when there is a file with http values' do
      let(:datastore) do
        temp_file = create_tempfile("https://www.example.com/\n127.0.0.1")
        store = ModuleDatastore.new(
          {
            'RHOSTS' => "file:#{temp_file}"
          },
          mod
        )
        store.import_options(mod.options)
        store
      end

      it 'calculates the required targets' do
        expected = [
          {"HttpPassword"=>"", "HttpUsername"=>"", "RHOSTS"=>"www.example.com", "RPORT"=>443, "SSL"=>true, "TARGETURI"=>"/", "URI"=>"/", "VHOST"=>"www.example.com"},
          { "RHOSTS" => "127.0.0.1", "RPORT" => 8080 },
        ]
        expect(mod.get_targets.to_a.map(&:to_h)).to eq(expected)
      end
    end
  end
end
