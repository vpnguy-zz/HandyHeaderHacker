#!/usr/bin/env python2
from argparse import RawTextHelpFormatter
import argparse
import sys
import urllib2
import datetime
import ssl #For SSL context modification

#Still very active in development, please no bully

def ReferrerPolicy(searchheaders):
	for header in searchheaders:
		if "Referrer-Policy:".lower() in header.lower():
			print "\033[1;32m[+]\033[0m Detected Referrer-Policy - '" + header.rstrip() + "' \033[1;32m(OK)\033[0m"
			return
	print "\033[1;31m[-]\033[0m Referrer-Policy not present \033[1;31m(Not OK)\033[0m"	
def XFrameOptions(searchheaders):
	for header in searchheaders:
		if "X-Frame-Options:".lower() in header.lower():
			print "\033[1;32m[+]\033[0m Detected X-Frame-Options - '" + header.rstrip() + "' \033[1;32m(OK)\033[0m"
			return
	print "\033[1;31m[-]\033[0m X-Frame-Options not present \033[1;31m(Not OK)\033[0m"		
def ContentSecurityPolicy(searchheaders):
	detected = False
	for header in searchheaders:
		if "Content-Security-Policy:".lower() in header.lower():
			print "\033[1;32m[+]\033[0m Detected Content-Security-Policy - '" + header.rstrip() + "' \033[1;32m(OK)\033[0m"
			detected = True
		if "X-Webkit-CSP:".lower() in header.lower():
			print "\033[1;32m[+]\033[0m Detected X-Webkit-CSP - '" + header.rstrip() + "' \033[1;32m(OK)\033[0m"
			detected = True
		if "X-Content-Security-Policy:".lower() in header.lower():
			print "\033[1;32m[+]\033[0m Detected X-Content-Security-Policy - '" + header.rstrip() + "' \033[1;32m(OK)\033[0m"
			detected = True

	#Report Only
		if "Content-Security-Policy-Report-Only:".lower() in header.lower():
			print "\033[1;33m[I]\033[0m Detected Content-Security-Policy in report only - '" + header.rstrip() + "' \033[1;33m(Informational)\033[0m"
			detected = True
		if "X-Webkit-CSP-Report-Only:".lower() in header.lower():
			print "\033[1;33m[I]\033[0m Detected X-Webkit-CSP in report only - '" + header.rstrip() + "' \033[1;33m(Informational)\033[0m"
			detected = True
		if "X-Content-Security-Policy-Report-Only:".lower() in header.lower():
			print "\033[1;33m[I]\033[0m Detected X-Content-Security-Policy in report only  - '" + header.rstrip() + "' \033[1;33m(Informational)\033[0m"
			detected = True
	#Any headers?
	if detected is True:
		return
	else:
		print "\033[1;31m[-]\033[0m Content-Security-Policy not present \033[1;31m(Not OK)\033[0m"	

def XXSSProtection(searchheaders):
	for header in searchheaders:
		if "X-XSS-Protection:".lower() in header.lower():
			print "\033[1;32m[+]\033[0m Detected X-XSS-Protection - '" + header.rstrip() + "' \033[1;32m(OK)\033[0m"
			return
	print "\033[1;31m[-]\033[0m X-XSS-Protection not present \033[1;31m(Not OK)\033[0m"
def XContentTypeOptions(searchheaders):
	for header in searchheaders:
		if "X-Content-Type-Options:".lower() in header.lower():
			print "\033[1;32m[+]\033[0m Detected X-Content-Type-Options - '" + header.rstrip() + "' \033[1;32m(OK)\033[0m"
			return
	print "\033[1;31m[-]\033[0m X-Content-Type-Options not present \033[1;31m(Not OK)\033[0m"

def GeneralInspect(searchheaders):
	serverversion = ""
	for header in searchheaders:
		if "Server: ".lower() in header.lower() and header.startswith("Server:"):
			print "\033[1;33m[I]\033[0m Detected Server header - '" + header.rstrip() + "' \033[1;33m(Informational)\033[0m"
			serverversion = header
		if "ETag: ".lower() in header.lower():
			if "Apache".lower() in serverversion.lower():
				print "\033[1;33m[I]\033[0m Detected ETag Apache - '" + header.rstrip() + "' \033[1;33m(Informational)\033[0m"
			else:
				print "\033[1;34m[I]\033[0m Possible ETag - '" + header.rstrip() + "' \033[1;34m(Possible Informational)\033[0m"
		if "X-Powered-By: ".lower() in header.lower():
			print "\033[1;33m[I]\033[0m Detected X-Powered-By - '" + header.rstrip() + "' \033[1;33m(Informational)\033[0m"

def CookieInspection(searchheaders):
	for header in searchheaders:
		if "Set-Cookie:".lower() in header.lower():
			CookieSplit = header.split(';')
			del CookieSplit[0]
			CookieSplit[-1] = CookieSplit[-1].rstrip()
			CookieString = ''.join(CookieSplit)
			if "HttpOnly".lower() not in CookieString.lower():
				print "\033[1;31m[-]\033[0m Cookie not marked HttpOnly - '" + header.rstrip() + "' \033[1;31m(Not OK)\033[0m"
			if "Secure".lower() not in CookieString.lower():
				print "\033[1;31m[-]\033[0m Cookie not marked Secure - '" + header.rstrip() + "' \033[1;31m(Not OK)\033[0m"
def SecureChecks(searchheaders):
	headerlist = ''.join(searchheaders)
	if "Strict-Transport-Security:".lower() in headerlist.lower():
		HSTSHeader = filter(lambda y: 'Strict-Transport-Security'.lower() in y.lower(),searchheaders)
		print "\033[1;32m[+]\033[0m Detected Strict-Transport-Security - " + HSTSHeader[0].rstrip() + "' \033[1;32m(OK)\033[0m"
	else:
		print "\033[1;31m[-]\033[0m Strict-Transport-Security not present \033[1;31m(Not OK)\033[0m"
	if "Public-Key-Pins:".lower() in headerlist.lower():
		PKPHeader = filter(lambda y: 'Public-Key-Pins'.lower() in y.lower(),searchheaders)
		print "\033[1;32m[+]\033[0m Detected Public-Key-Pins - " + PKPHeader[0].rstrip() + "' \033[1;32m(OK)\033[0m"
	else:
		print "\033[1;31m[-]\033[0m Public-Key-Pins not present \033[1;31m(Not OK)\033[0m"

def AnomalousHeaders(searchheaders):
	KnownHeaders = ['HTTP/1.1','Date','Server', 'Last-Modified','ETag','Accept-Ranges','Content-Length','Vary','Cache-Control','Content-Type','Pragma','Transfer-Encoding','Connection','Set-Cookie', 'Expires', 'WWW-Authenticate', 'Content-Encoding','Age','Status', 'Content-Range','Content-Language','Public-Key-Pins','Strict-Transport-Security','ETag', 'X-Powered-By', 'X-Content-Type-Options', 'X-XSS-Protection', 'Content-Security-Policy','X-Frame-Options', 'Referrer-Policy' ]
	for header in searchheaders:
		if not any(y.lower() in header.lower() for y in KnownHeaders):
			print "\033[1;34m[I]\033[0m Anomalous Header detected '" + header.rstrip() + "' \033[1;34m(Possible Informational)\033[0m"

def RetrieveHeader(Target, **cookiekey):
	ReplyHeaders = ""
	CookieGlobal = ""
	if 'cookie' in cookiekey: #detect if keyword function param is set
		CookieGlobal =  cookiekey['cookie']

	if "http" not in Target[:4].lower():
		print "You must specify a protocol (\"http\" or \"https\")"
		sys.exit(0)
	if "https" in Target[:5]:
		sslcontext = ssl.create_default_context()
		if args.insecure:
			print "Ignoring certificate errors..."
			sslcontext = ssl._create_unverified_context() #Ignore all SSL context 
		try:
			Cookies = {}
			if len(CookieGlobal) > 0:
				print "Using provided cookie..."
				Cookies = {"Cookie" : CookieGlobal}
			
			RequestFormed = urllib2.Request(Target, headers=Cookies)
			ReplyHeaders = urllib2.urlopen(RequestFormed, context=sslcontext).headers.headers
		except urllib2.HTTPError, e:
			print "HTTP error " + str(e.code) + ", going on..."
			ReplyHeaders = str(e.headers).split("\n")
		except ssl.CertificateError:
			print "SSL Certificate error, ignore with -k flag"
			sys.exit(0)
		return ReplyHeaders
	else:
		if len(CookieGlobal) > 0:
			print "Using provided cookie..."
			RequestFormed = urllib2.Request(Target,  headers={"Cookie" : CookieGlobal})
			ReplyHeaders = urllib2.urlopen(RequestFormed).headers.headers
		else:
			ReplyHeaders = urllib2.urlopen(Target).headers.headers
		return ReplyHeaders

def CookieList(string):
	return string.split(';')


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="""

			Handy Header Hacker (HHH)
				by DarkRed
			Examine HTTP response headers for common security issues
				Ver: 1.3 - 1/11/2018
				Ver: 1.4 - 6/08/2019


		""",formatter_class=RawTextHelpFormatter)
	Required = parser.add_argument_group('Required')
	Required.add_argument('-t','--target', help='URL of HTTP service to inspect ex: "-t http://github.com"', required=True)

	#Optional
	parser.add_argument('-s','--securechecks', help='Inspect only headers related to HTTPS on target', required=False, action='store_true')
	parser.add_argument('-xf','--xframeoptions', help='Inspect only the X-Frame-Options header on target', required=False, action='store_true')
	parser.add_argument('-xx','--xxssprotection', help='Inspect only the X-XSS-Protection header on target', required=False, action='store_true')
	parser.add_argument('-xc','--xcontenttypeoptions', help='Inspect only the X-Content-Type-Options header on target', required=False, action='store_true')
	parser.add_argument('-g','--general', help='Inspect general headers on target', required=False, action='store_true')
	parser.add_argument('-c','--cookies', help='Inspect cookies on target', required=False, action='store_true')
	parser.add_argument('-a','--headers', help='Inspect anomalous headers on target', required=False, action='store_true')
	parser.add_argument('-k','--insecure', help='Ignore certificate errors on the remote host', required=False, action='store_true')
	parser.add_argument('-rf','--refpolicy', help='Inspect only the Referrer-Policy header on target', required=False, action='store_true')
	parser.add_argument('-b','--cookie', help='Pass a cookie to your request to simulate an authenticated user, EX: ./hhh.py -t https://google.com -b "cookie1=test;cookie2=google', required=False, type=CookieList)

	args = parser.parse_args()
	multiarg = False 
	print "Starting Handy Header Hacker... "
	CookieGlobal = "" #Define an empty cookie variable
	if args.cookie:
		delim = ';'
		CookieGlobal = delim.join(args.cookie)
	

	if args.securechecks:
		multiarg = True
		if  "https" in args.target[:5]:
			print "Attempting checks against HTTPS headers on " + args.target
			Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
			SecureChecks(Headers)
		else:
			print "Target is not utilizing HTTPS, exiting..."
			sys.exit(0)
	if args.refpolicy:
		multiarg = True
		print "Attempting check against Referrer-Policy header on " + args.target
		Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
		ReferrerPolicy(Headers)
	if args.xframeoptions:
		multiarg = True
		print "Attempting check against X-Frame-Options header on " + args.target
		Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
		XFrameOptions(Headers)
	if args.xxssprotection:
		multiarg = True
		print "Attempting check against X-XSS-Protection header on " + args.target
		Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
		XXSSProtection(Headers)
	if args.xcontenttypeoptions:
		multiarg = True
		print "Attempting check against X-Content-Type-Options header on " + args.target
		Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
		XContentTypeOptions(Headers)
	if args.general:
		multiarg = True
		print "Attempting general header checks on " + args.target
		Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
		GeneralInspect(Headers)
	if args.cookies:
		multiarg = True
		print "Attempting cookie checks on " + args.target
		Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
		CookieInspection(Headers)
	if args.headers:
		multiarg = True
		print "Attempting anomalous header check on " + args.target
		Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
		AnomalousHeaders(Headers)

	if multiarg == False:	#Do not run all checks if checks specified
		print "Launching Handy Header Hacker against: " + args.target
		Headers = RetrieveHeader(args.target, cookie=CookieGlobal)
		XFrameOptions(Headers)
		ContentSecurityPolicy(Headers)
		XXSSProtection(Headers)
		XContentTypeOptions(Headers)
		GeneralInspect(Headers)
		CookieInspection(Headers)
		ReferrerPolicy(Headers)
		if "https" in args.target[:5]:
			SecureChecks(Headers)
		AnomalousHeaders(Headers)
	print 'Completed at: {:%H:%M:%S on %m-%d-%Y}'.format(datetime.datetime.now())
	sys.exit(0)
