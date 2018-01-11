![Supported Python versions](https://img.shields.io/badge/python-2.7-blue.svg)
# HandyHeaderHacker
HandyHeaderHacker is a script to examine HTTP responses from a server for best security practices. While HandyHeaderHacker is nowhere near completion it is in a state where you can quickly analyze a web server with a single request.


## Current headers inspected
- X-Frame-Options
- Content-Security-Policy (Including Report-Only)
- X-Webkit-CSP
- X-XSS-Protection
- X-Content-Type-Options
- Server
- Etag
- X-Powered-By
- Set-Cookie and associated cookie flags
- Strict-Transport-Security
- Public-Key-Pins
- Referrer-Policy


## Usage ##
    hhh.py [-h] -t TARGET [-s] [-xf] [-xx] [-xc] [-g] [-c] [-a] [-k] [-rf]

			Handy Header Hacker (HHH)
				by DarkRed
			Examine HTTP response headers for common security issues
				Ver: 1.3 - 1/11/2017
		
    optional arguments:
      -h, --help Show this help message and exit
      -s, --securechecks Inspect only headers related to HTTPS on target
      -xf, --xframeoptions  Inspect only the X-Frame-Options header on target
      -xx, --xxssprotection Inspect only the X-XSS-Protection header on target
      -xc, --xcontenttypeoptions Inspect only the X-Content-Type-Options header on target
      -g, --general Inspect general headers on target
      -c, --cookies Inspect cookies on target
      -a, --headers Inspect anomalous headers on target
      -k, --insecure Ignore certificate errors on the remote host
      -rf, --refpolicy Inspect only the Referrer-Policy header on target
	  -b COOKIE, --cookie COOKIE Pass a cookie to your request to simulate an authenticated user, EX: ./hhh.py -t https://google.com -b "cookie1=test;cookie2=google


    
    Required:
      -t TARGET, --target TARGET URL of HTTP service to inspect ex: "-t http://github.com"


