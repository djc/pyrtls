import ssl
import socket
import sys

def setup():
    return ssl.create_default_context()

def request(ctx):
    sock = socket.socket()
    sock = ctx.wrap_socket(sock, server_hostname='xavamedia.nl')
    sock.connect(('xavamedia.nl', 443))
    sock.send(b'GET / HTTP/1.1\r\nHost: xavamedia.nl\r\nConnection: close\r\n\r\n')
    return sock.recv(8192)

if __name__ == '__main__':
    print(request(setup()))
