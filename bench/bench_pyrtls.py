import pyrtls
import socket
import sys

def setup():
    return pyrtls.ClientConfig()

def request(config):
    sock = socket.socket()
    sock = config.wrap_socket(sock, 'xavamedia.nl')
    sock.connect(('xavamedia.nl', 443))
    sock.send(b'GET / HTTP/1.1\r\nHost: xavamedia.nl\r\nConnection: close\r\n\r\n')
    return sock.recv(8192)

if __name__ == '__main__':
    print(request(setup()))
