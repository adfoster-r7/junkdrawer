require 'socket'
#
# socket = Socket.new(Socket::Constants::AF_INET, Socket::Constants::SOCK_STREAM, 0)
# sockaddr = Socket.pack_sockaddr_in( 5555, '127.0.0.1' )
# puts 'binding'
# socket.bind(sockaddr)
# socket.listen(1)
#
# puts 'listening'
# client_socket, client_info = socket.accept
# puts 'got connection'
#
# loop do
#   command = $stdin.gets
#   client_socket.write(command)
#   puts client_socket.gets
# end

# result = IO.select([$stdin])
# while !$stdin.eof?
#   puts $stdin.gets
# end

# require 'open3'
#
# p_stdin, p_stdout, p_stderr, _wait_thr = Open3.popen3('/bin/bash')
#
# loop do
#   ready_listeners, *_other_listeners = IO.select([$stdin, p_stdout, p_stderr])
#   ready_listeners.each do |listener|
#     case listener
#     when $stdin
#       p_stdin.write($stdin.gets)
#     when p_stdout
#       $stdout.write(p_stdout.gets)
#     when p_stderr
#       $stderr.write(p_stderr.gets)
#     end
#   end
# end

# READ/WRITE from popen3
# READ/WRITE from popen3
# READ/WRITE from popen3
# READ/WRITE from popen3

require 'readline'
require 'io/console'
require 'open3'

def ctrl_c?(char)
  char == "\u0003"
end

p_stdin, p_stdout, p_stderr, _wait_thr = Open3.popen3('/bin/sh -i')

IO.console.raw!

loop do
  ready_listeners, *_other_listeners = IO.select([$stdin, p_stdout, p_stderr])
  ready_listeners.each do |listener|
    case listener
    when $stdin
      char = $stdin.getch
      if ctrl_c?(char)
        IO.console.cooked!
        puts "ctrl+c sent"
        exit 130
      end
      p_stdin.write(char)
    when p_stdout
      $stdout.write(p_stdout.getc)
    when p_stderr
      $stderr.write(p_stderr.getc)
    end
  end
end
#
# require 'socket'
# require 'io/console'
# require 'open3'
#
# def ctrl_c?(char)
#   char == "\u0003"
# end
#
# def negotiate_pty(client_socket)
#   # Hope for a python3 pty on connection, presumably we'd want some sort of detection here, etc.
#   client_socket.write(%{python3 -c 'import pty; pty.spawn("/bin/bash")'\n})
#   is_pty = true
#   is_pty
# end
#
# socket = Socket.new(Socket::Constants::AF_INET, Socket::Constants::SOCK_STREAM, 0)
# sockaddr = Socket.pack_sockaddr_in(5555, '127.0.0.1')
# socket.bind(sockaddr)
# socket.listen(1)
#
# puts 'listening on 5555'
# begin
#   begin
#     client_socket, _client_info = socket.accept_nonblock
#   rescue IO::WaitReadable, Errno::EINTR
#     IO.select([socket])
#     retry
#   end
#   puts 'got connection, entering raw mode'
#
#   IO.console.raw!
#   is_pty = negotiate_pty(client_socket)
#   loop do
#     # TODO: stderr might get dropped depending on the connection
#     ready_listeners, *_other_listeners = IO.select([$stdin, client_socket])
#     # puts ready_listeners.inspect
#     ready_listeners.each do |listener|
#       case listener
#       when $stdin
#         char = $stdin.getch
#         if ctrl_c?(char)
#           IO.console.cooked!
#           puts 'ctrl+c sent'
#           exit 130
#         end
#         #  If we're _not_ in a pty, we'll want to echo the input char to stdout
#         if !is_pty
#           puts char
#         end
#         client_socket.write(char)
#       when client_socket
#         $stdout.write(client_socket.getc)
#       end
#     end
#   end
# ensure
#   IO.console.cooked!
# end
