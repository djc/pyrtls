import pyrtls
import socket
import sys

def main():
    print(pyrtls.__file__)
    client_config = pyrtls.ClientConfig()
    sock = socket.socket()
    sock = client_config.wrap_socket(sock, 'xavamedia.nl')
    sock.connect(('xavamedia.nl', 443))
    print(sock.send(b'GET / HTTP/1.0\r\nHost: xavamedia.nl\r\nConnection: close\r\n\r\n'))
    print(repr(sock.recv(8192)))

def echo_server():
    with open('tests/ee-certificate.pem', 'r') as f:
        cert_pem = f.read()
    with open('tests/ee-key.pem', 'r') as f:
        key_pem = f.read()

    server_config = pyrtls.ServerConfig([cert_pem], key_pem)
    listener = socket.socket()
    listener.bind(('0.0.0.0', 8192))
    listener.listen()
    sock, addr = listener.accept()
    sock = server_config.wrap_socket(sock)

    req = sock.recv(5)
    print(repr(req))
    print(sock.send(req))

def echo_client():
    client_config = pyrtls.ClientConfig()
    sock = socket.socket()
    sock = client_config.wrap_socket(sock, 'localhost')
    sock.connect(('127.0.0.1', 8192))
    print(sock.send('HELLO'))
    print(repr(sock.recv(5)))

if __name__ == '__main__':
    if len(sys.argv) == 1:
        main()
    elif sys.argv[1] == 'server':
        echo_server()
    elif sys.argv[1] == 'client':
        echo_client()
    else:
        print('unknown command: {}'.format(sys.argv[1]))
