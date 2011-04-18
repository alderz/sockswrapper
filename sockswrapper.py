#!/usr/bin/env python
# -*- coding: utf-8 -*-

__doc__ = """Sockswrapper

Sockswrapper is a HTTP proxy that sends all the traffic through
a SOCKS proxy.

localhost -> sockswrapper -> SOCKS proxy -> internet

It is based in Tiny HTTP Proxy by SUZUKI Hisao.

This module implements GET, HEAD, POST, PUT and DELETE methods
on BaseHTTPServer, and behaves as an HTTP proxy.  The CONNECT
method is also implemented experimentally, but has not been
tested yet.

Any help will be greatly appreciated.

Original autor: SUZUKI Hisao.
Socks part by: Ángel Alonso.
"""

__version__ = "0.3"

import BaseHTTPServer
import select
import socket
import SocketServer
import urlparse 
import socks
import sys
import getopt

class ProxyHandler (BaseHTTPServer.BaseHTTPRequestHandler):
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle

    server_version = "sockswrapper/" + __version__
    rbufsize = 0                        # self.rfile Be unbuffered

    def handle(self):
        (ip, port) =  self.client_address
        if hasattr(self, 'allowed_clients') and ip not in self.allowed_clients:
            self.raw_requestline = self.rfile.readline()
            if self.parse_request(): self.send_error(403)
        else:
            self.__base_handle()

    def _connect_to(self, netloc, soc):
        i = netloc.find(':')
        if i >= 0:
            host_port = netloc[:i], int(netloc[i+1:])
        else:
            host_port = netloc, 80
        print "\t" "connect to %s:%d" % host_port
        try: soc.connect(host_port)
        except socket.error, arg:
            try: msg = arg[1]
            except: msg = arg
            self.send_error(404, msg)
            return 0
        return 1

    def do_CONNECT(self):
        soc = socks.socksocket()
        soc.setproxy(socks.PROXY_TYPE_SOCKS5, self.socks_host, port=self.socks_port)
        try:
            if self._connect_to(self.path, soc):
                self.log_request(200)
                self.wfile.write(self.protocol_version +
                                 " 200 Connection established\r\n")
                self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
                self.wfile.write("\r\n")
                self._read_write(soc, 300)
        finally:
            soc.close()
            self.connection.close()

    def do_GET(self):
        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(
            self.path, 'http')
        if scm != 'http' or fragment or not netloc:
            self.send_error(400, "bad url %s" % self.path)
            return
        soc = socks.socksocket()
        soc.setproxy(socks.PROXY_TYPE_SOCKS5, self.socks_host, port=self.socks_port)
        try:
            if self._connect_to(netloc, soc):
                self.log_request()
                soc.send("%s %s %s\r\n" % (
                    self.command,
                    urlparse.urlunparse(('', '', path, params, query, '')),
                    self.request_version))
                self.headers['Connection'] = 'close'
                del self.headers['Proxy-Connection']
                for key_val in self.headers.items():
                    soc.send("%s: %s\r\n" % key_val)
                soc.send("\r\n")
                self._read_write(soc)
        finally:
            soc.close()
            self.connection.close()

    def _read_write(self, soc, max_idling=20):
        iw = [self.connection, soc]
        ow = []
        count = 0
        while 1:
            count += 1
            (ins, _, exs) = select.select(iw, ow, iw, 3)
            if exs: break
            if ins:
                for i in ins:
                    if i is soc:
                        out = self.connection
                    else:
                        out = soc
                    data = i.recv(8192)
                    if data:
                        out.send(data)
                        count = 0
            else:
                print "\t" "idle", count
            if count == max_idling: break

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET

class ThreadingHTTPServer (SocketServer.ThreadingMixIn,
                           BaseHTTPServer.HTTPServer): pass

if __name__ == '__main__':
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "h", ["help"])
    except getopt.GetoptError, err:
        print str(err)
        print sys.argv[0], "socks_host socks_port [port [allowed_client_name ...]]"
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            print sys.argv[0], "socks_host socks_port [port [allowed_client_name ...]]"
            sys.exit()
        else:
            assert False, "unhandled option"

    if len(args) < 2:
        print sys.argv[0], "socks_host socks_port [port [allowed_client_name ...]]"
        sys.exit()

    ProxyHandler.socks_host = args[0]
    ProxyHandler.socks_port = int(args[1])
    port = 8080

    if args[2:]:
        port = args[2]
        allowed = []
        for name in args[3:]:
            client = socket.gethostbyname(name)
            allowed.append(client)
            print "Accept: %s (%s)" % (client, name)
        ProxyHandler.allowed_clients = allowed
        del args[2:]
    else:
        print "[+] Any clients will be served..."

    ProxyHandler.protocol_version = "HTTP/1.0"
    httpd = ThreadingHTTPServer(('', port), ProxyHandler)
    sa = httpd.socket.getsockname()
    print "[!] Sockswrapper listening on", sa[0], "port", sa[1], "..."

    httpd.serve_forever()
