Raw HTTP request:
```
printf "GET / HTTP/1.1\r\n" | ncat localhost 8000
```

Curl through socks:
```
curl -v --socks4a localhost:5555 http://localhost:800
```

With ncat, doesn't work on 7.91
```

```
