import pyrtls
import socket

def main():
    print(pyrtls.__file__)
    client_config = pyrtls.ClientConfig()
    sock = socket.socket()
    sock = client_config.wrap_socket(sock, 'xavamedia.nl')
    sock.connect(('xavamedia.nl', 443))
    print(sock.send(b'GET / HTTP/1.0\r\nHost: xavamedia.nl\r\nConnection: close\r\n\r\n'))
    print(repr(sock.recv(8192)))

if __name__ == '__main__':
    main()
