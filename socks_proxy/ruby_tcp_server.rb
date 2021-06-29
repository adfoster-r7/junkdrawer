require 'socket'

server = TCPServer.new '', 2000
loop do
  Thread.start(server.accept) do |client|
    # Skip request information
    puts client.gets

    response = []
    response << "HTTP/1.0 200 OK\r\n"
    response << "Server: SimpleHTTP/0.6 Python/2.7.16\r\n"
    response << "Date: Fri, 04 Jun 2021 11:17:05 GMT\r\n"
    response << "Content-type: text/html; charset=utf-8\r\n"
    response << "Content-Length: 11\r\n"
    response << "\r\n"
    response << "hello world"

    response.each do |line|
      client.write(line)
      sleep 1
    end
    client.close
  end
end
