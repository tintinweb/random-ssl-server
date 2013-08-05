# -*- coding: utf-8 -*-
'''
Created on 31.07.2013

@author: martin
'''
import socket
from SocketServer import BaseServer
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from OpenSSL import SSL



class SecureHTTPServer(HTTPServer):
    class Handler(SimpleHTTPRequestHandler):
        def setup(self):
            self.connection = self.request
            self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
            self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)
    
    def __init__(self, server_address):
        self.server_address=server_address
        
    def setup_socket(self):
        BaseServer.__init__(self, self.server_address, SecureHTTPServer.Handler)
        self.socket=socket.socket(self.address_family, self.socket_type)
        self.server_bind()
        self.server_activate()
        
    def sslify(self,certfile,keyfile=None):
        keyfile = keyfile or certfile
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.use_privatekey_file (certfile)
        ctx.use_certificate_file(keyfile)
        self.setup_socket()
        self.socket = SSL.Connection(ctx, self.socket)
        