require 'socket'
require 'io/console'
require 'open3'
require 'bindata'

module SocketPair
  attr_accessor :other_socket
  attr_accessor :type

  def state
    if type == :lhost
      @state
    else
      other_socket.state
    end
  end

  def state=(state)
    if type != :lhost
      raise 'Unexpected'
    end
    @state = state
  end
end

# Initial socks request sent by the client
class Request < BinData::Record
  # The network byte order is defined to always be big-endian
  endian :big

  # Should be 0x04 for socks4a
  uint8 :version
  # 0x01 = Establish a TCP/IP stream connection
  # 0x02 = Establish a TCP/IP port binding
  uint8 :command
  # 2-byte port number (in network order)
  uint16 :remote_port
  # Ipv4 address, 4 bytes (in network order)
  uint32 :remote_address

  # variable length, null terminated
  stringz :id

  # SOCKS4a extends the SOCKS4 protocol to allow a client to specify a destination
  # domain name rather than an IP address
  stringz :remote_domain_name, onlyif: :has_domain_name?

  def has_domain_name?
    # Only parse a domain_name if the remote_address matches 0.0.0.x and x is non-zero
    (remote_address & 0xFFFFFF00) == 0x00000000 &&
      (remote_address & 0x000000FF) != 0x00
  end
end

# 0x5A - Request granted
# 0x5b - Request rejected or afiled
# 0x5C - Request failed because client is not running identd (or not reachable from server)
# 0x5D - Request failed because client's identd could not confirm the user id in the request
class ResponseCode
  Granted = 0x5A
  Rejected = 0x5B
  IdentdNotRunning = 0x5C
  IdentdFailed = 0xD5
end

# Initial socks response sent by the server
class Response < BinData::Record
  # The network byte order is defined to always be big-endian
  endian :big

  # Version, null byte for 4a
  uint8 :version

  # One of ResponseCode
  uint8 :response_code

  uint16 :remote_port
  uint32 :remote_address
end

def resolve_ipv4_address(domain, port)
  Addrinfo.getaddrinfo(domain.to_s, port.to_i, nil, :STREAM)
          .select(&:ipv4?)
          .first
    &.ip_address
end

def open_remote_connection(port:, address:)
  socket = Socket.new(Socket::Constants::AF_INET, Socket::Constants::SOCK_STREAM, 0)
  sockaddr = Socket.pack_sockaddr_in(port, address)
  socket.connect(sockaddr)

  socket
end

class SocketManager
  include MonitorMixin

  def initialize
    super
    @socket_pairs = []
  end

  def register(socket)
    synchronize do
      @socket_pairs.push(socket)
    end
  end

  def remove(socket)
    synchronize do
      @socket_pairs.delete(socket)
    end
  end

  def to_a
    synchronize do
      @socket_pairs
    end
  end
end

@socket_manager = SocketManager.new

# Listener that accepts new sockets, and queues them up for later execution
socket_accepting_thread = Thread.new do
  socket = Socket.new(Socket::Constants::AF_INET, Socket::Constants::SOCK_STREAM, 0)
  socket.setsockopt(:SOCKET, :REUSEADDR, true)
  sockaddr = Socket.pack_sockaddr_in(5555, '0.0.0.0')
  socket.bind(sockaddr)
  socket.listen(5)
  puts 'listening on 5555'

  loop do
    begin
      client_socket, _client_info = socket.accept_nonblock
      client_socket.extend(SocketPair)
      client_socket.type = :lhost
      client_socket.state = :hand_shake
      @socket_manager.register(client_socket)
    rescue IO::WaitReadable, Errno::EINTR
      IO.select([socket])
      retry
    end
  end
end

def close_socket(socket)
  begin
    socket.shutdown
  rescue => e
    puts "failed to shutdown"
    puts e
  end

  begin
    socket.close
  rescue => e
    puts "failed to close"
    puts e
  end

  @socket_manager.remove(socket)
ensure
  if socket.other_socket
    other_socket = socket.other_socket
    socket.other_socket = nil
    close_socket(other_socket)
  end
end

  def make_response(response_code)
    Response.new(
      version: 0,
      # Granted
      response_code: response_code,
      # Only set when binding, which isn't supported
      remote_port: 0,
      remote_address: 0
    )
  end

  # Listener that accepts new sockets, handling any read/writes
  read_write_thread = Thread.new do
    begin
      loop do
        # TODO: Timeout is a bit lame?
        ready_listeners, *_other_listeners = IO.select(@socket_manager.to_a, nil, nil, 0.1)
        puts (ready_listeners.to_a + _other_listeners).inspect
        ready_listeners.to_a.each do |listener|
          lhost = listener.type == :lhost ? listener : listener.other_socket
          rhost = listener.type != :lhost ? listener : listener.other_socket

          case listener
          when lhost
            case lhost.state
            when :hand_shake
              # TODO: Learn how to buffer/stream into a BinData object
              sleep 0.2
              puts 'negotiating handle shake lhost'
              raw_request = lhost.recv(1024)
              begin
                request = Request.read(raw_request)
              rescue
                lhost.write(make_response(ResponseCode::Rejected).to_binary_s)
                close_socket(lhost)
                next
              end

              # resolve the domain if supplied
              remote_address =
                if request.remote_domain_name.empty?
                  # Find ipv4 address
                  request.remote_address.to_i
                else
                  resolve_ipv4_address(request.remote_domain_name, request.remote_port)
                end
              remote_port = request.remote_port.to_i

              # Open a remote connection
              puts 'connecting to rhost'
              begin
                rhost = open_remote_connection(port: remote_port, address: remote_address)
              rescue => e
                puts e
                begin
                  rhost.shutdown
                  rhost.close
                rescue => e
                  puts 'failed to shutdown socket'
                end

                lhost.write(make_response(ResponseCode::Rejected).to_binary_s)
                close_socket(lhost)
                next
              end

              rhost.extend(SocketPair)
              rhost.other_socket = lhost
              lhost.other_socket = rhost
              lhost.state = :streaming
              @socket_manager.register(rhost)
              lhost.write(make_response(ResponseCode::Granted).to_binary_s)
            when :streaming
              data = lhost.recv(512)
              if data.empty?
                puts 'lhost disconnected'
                close_socket(lhost)
                next
              end
              rhost.write(data)
            else
              raise 'something went terribly wrong'
            end
          when rhost
            data = rhost.recv(512)
            if data.empty?
              puts 'rhost disconnected'
              close_socket(lhost)
              close_socket(rhost)
              next
            end
            lhost.write(data)
          end
        end
      end
    end
  end

  [socket_accepting_thread, read_write_thread].each(&:join)
