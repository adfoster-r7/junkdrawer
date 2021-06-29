# require 'socket'
# require 'fiber'
#
# include Socket::Constants
#
# def random_delay
#   # sleep 1
# end
#
# def handle_http_request(client_socket)
#   # Ignore the first line - i.e. `GET / HTTP/1.1\r\n`
#   puts client_socket.gets
#   response = []
#   response << "HTTP/1.0 200 OK\r\n"
#   response << "Server: SimpleHTTP/0.6 Python/2.7.16\r\n"
#   response << "Date: Fri, 04 Jun 2021 11:17:05 GMT\r\n"
#   response << "Content-type: text/html; charset=utf-8\r\n"
#   response << "Content-Length: 11\r\n"
#   response << "\r\n"
#   response << "hello world"
#
#   response.each do |line|
#     client_socket.write(line)
#     sleep 1
#   end
#   # begin
#   #   client_socket.shutdown
#   # rescue => e
#   #   puts 'failed to shutdown'
#   #   puts e
#   # end
#   begin
#     puts '1: shutting down'
#     client_socket.shutdown
#     puts '2: closing'
#     client_socket.close
#   rescue => e
#     puts 'failed to shutdown:'
#     puts e
#
#     begin
#       client_socket.close
#     rescue => e
#       puts 'failing to close'
#       puts e
#     end
#   end
# end
#
# def main
#
#
#   sockets = [server_socket]
#
#   puts 'starting on 8000'
#   loop do
#     client_socket, client_addrinfo = socket.accept_nonblock
#
#     ready_listeners, *_others = IO.select(sockets, nil, nil, nil)
#
#     ready_listeners.each do |listener|
#       case listener
#       when server_socket
#         client_socket, _client_info = server.accept
#         sockets.push(client_socket)
#       else
#
#       end
#     end
#   end
# end
#
# Fiber.new do
#   server_socket = Socket.new(AF_INET, SOCK_STREAM, 0)
#   server_socket.setsockopt(:SOCKET, :REUSEADDR, true)
#   sockaddr = Socket.pack_sockaddr_in(8000, '0.0.0.0')
#   server_socket.bind(sockaddr)
#   server_socket.listen(5)
#
#   fibers =
#
#   loop do
#
#   end
# end
#
# if __FILE__ == $0
#   main
# end

require 'socket'
require 'fiber'

class Reactor
  def initialize
    @readable = {}
    @writeable = {}
  end

  def run
    while @readable.any? || @writeable.any?
      readable, writeable = IO.select(@readable.keys, @writeable.keys)
      readable.each do |io|
        @readable[io].resume
      end

      writeable.each do |io|
        @writeable[io].resume
      end
    end
  end

  def await_readable(io)
    @readable[io] = Fiber.current
    Fiber.yield
    @readable.delete(io)
  end

  def await_writeable(io)
    @writeable[io] = Fiber.current
    Fiber.yield
    @writeable.delete(io)
  end
end

reactor = Reactor.new
server_socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
server_socket.setsockopt(:SOCKET, :REUSEADDR, true)
sockaddr = Socket.pack_sockaddr_in(8000, '0.0.0.0')
server_socket.bind(sockaddr)
server_socket.listen(5)

# @param [Reactor] reactor
def handle_connection(reactor, client_socket)
  request = reactor.await_readable(client_socket) do

  end

  request = client_socket.gets
  reactor.await_writeable(client_socket)

  # Echo and close
  client_socket.puts(request)
  client_socket.close
end

Fiber.new do
  loop do
    client_socket = reactor.await_readable(server_socket) do
      client_socket, _client_info = server_socket.accept
      client_socket
    end

    Fiber.new do
      handle_connection(reactor, client_socket)
    end.resume
  end
end.resume

reactor.run
