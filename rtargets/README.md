Expected scenarios to work:

```
set RHOSTS 10.10.10.10 # Will use default RPORT value
set RHOSTS 10.10.10.10/24 # CIDR with hosts and default RPORT value
set RHOSTS cidr:/24:http://10.10.10.10:10000/foo/bar
set RHOSTS http://10.10.10.10:10000
set RHOSTS file:... # Applies all of the above rules, including loading other files
```

Multiple values
```
set RHOSTS 10.10.10.10, cidr:/24:http://10.10.10.10/tomcat/manager, https://192.168.1.1:8080/manager/html
set RHOSTS file:... 
set RHOSTS 
```

Problem:
Should paths always override target URI? i.e. Are there any modules that would want a base of `http://10.10.10.10/foo`, and would have their own separate targeturi convention

What happens with something like:
```
set RHOSTS 10.10.10.10:8081, 10.10.10.10:8082
set RPORT 8080 
```

Or:

```
set RHOSTS http://10.10.10.10/foo/bar, https://10.10.10.10/tomcat 
set RPORT 8080
set RPATH /login
```

Or for RPORT being set before HTTP, what port should be used? 8080 or 80?
```
set RPORT 8080
set RHOSTS http://10.10.10.10/foo/bar
```

Or what shows for RTARGETS on a module that doesn't target http, but instead postgres
```
set RHOSTS 10.10.10.10
=> RHOSTS = 10.10.10.10:port
```

Forward planning, could we incorporate this to work with multiple RPATHs, like for LFI downloads/tomcat ghostcat?
```
set FILE /etc/passwd, /root/.ssh/id_rsa, /proc/self/cmdline, /WEB-INF/web.xml, /
```
