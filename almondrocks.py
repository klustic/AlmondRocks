#!/usr/bin/env python3
import argparse
import enum
import logging
import os
import select
import signal
import socket
import ssl
import struct
import sys
import threading


def proxy_sockets(s1, s2):
    while True:
        rlist = [s1, s2]
        r, _, _ = select.select(rlist, [], [], 1)
        if not r:
            continue
        if s1 in r:
            s2.write(s1.read(4096))
        elif s2 in r:
            s1.write(s2.read(4096))


def recv_all(sock, length):
    """
    Receive all of a specified number of bytes from a socket
    :param socket.socket sock: The socket to receive data from
    :param int length: The number of bytes of data to receive
    :raises ValueError: When the number of bytes is not received before reading EOF
    :return: The desired number of bytes
    :rtype: bytes
    """
    data = b''
    while len(data) < length:
        _data = sock.recv(length - len(data))
        if not _data:
            break
        data += _data
    if len(data) < length:
        raise ValueError('Received less data than desired before receiving EOF')
    return data


def counter(start=1):
    for i in range(start, 0xffffffff):
        yield i


class MessageType(enum.Enum):
    Control = 0
    Data = 1
    OpenChannel = 2
    CloseChannel = 3


class Message(object):
    HDR_STRUCT = b'!BHI'
    HDR_SIZE = struct.calcsize(HDR_STRUCT)

    def __init__(self, data, channel_id, msg_type=MessageType.Data):
        self.data = data  # type: bytes
        self._channel_id = channel_id  # type: int
        self.msg_type = msg_type  # type: MessageType
        self.logger = logging.getLogger('message')

    def __repr__(self):
        return '<Message type={} channel={} len={}>'.format(self.msg_type.name, self.channel_id, len(self.data))

    @property
    def channel_id(self):
        return self._channel_id

    @classmethod
    def parse_hdr(cls, data):
        msg_type, channel_id, length = struct.unpack(cls.HDR_STRUCT, data[:struct.calcsize(cls.HDR_STRUCT)])
        try:
            msg_type = MessageType(msg_type)
        except TypeError:
            raise TypeError('Parsing a message with an invalid message type: 0x{:02x}'.format(msg_type))
        return msg_type, channel_id, length

    @classmethod
    def parse(cls, data):
        msg_type, channel_id, length = struct.unpack(cls.HDR_STRUCT, data[:struct.calcsize(cls.HDR_STRUCT)])
        data = data[struct.calcsize(cls.HDR_STRUCT):]
        if length != len(data):
            raise ValueError('Parsing a message with an invalid length, received {} bytes, expected {}'.format(
                len(data), length))
        try:
            msg_type = MessageType(msg_type)
        except ValueError:
            raise ValueError('Parsing a message with an invalid message type: 0x{:02x}'.format(msg_type))
        return Message(data, channel_id, msg_type=MessageType(msg_type))

    def serialize(self):
        return struct.pack(self.HDR_STRUCT, self.msg_type.value, self.channel_id, len(self.data)) + self.data


class Channel(object):
    def __init__(self, channel_id):
        self._channel_id = channel_id
        self._client_end, self._tunnel_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.logger = logging.getLogger('channel')
        self.tx = 0
        self.rx = 0

    def __repr__(self):
        return '<Channel id={} bytes_tx={} bytes_rx={}>'.format(self.channel_id, self.tx, self.rx)

    @property
    def channel_id(self):
        return self._channel_id

    def fileno(self):
        return self._client_end.fileno()

    def close(self):
        self._tunnel_end.close()
        self._client_end.close()

    @property
    def tunnel_interface(self):
        """
        You can assume this supports the socket.socket stream interface
        :return: something for the tunnel to interact with
        :rtype: socket.socket
        """
        return self._tunnel_end

    @property
    def client_interface(self):
        """
        You can assume this supports the socket.socket stream interface
        :return: something for the tunnel to interact with
        :rtype: socket.socket
        """
        return self._client_end

    def send(self, data, flags=0):
        try:
            self.client_interface.sendall(data, flags)
        except Exception as e:
            self.logger.debug('Error sending through channel: {}'.format(e))
        else:
            self.tx += len(data)

    def recv(self, length):
        try:
            data = self.client_interface.recv(length)
        except Exception as e:
            self.logger.debug('Error sending through channel: {}'.format(e))
            data = b''
        else:
            self.rx += len(data)
        return data


class Tunnel(object):
    def __init__(self, sock, open_channel_callback=None, close_channel_callback=None):
        """

        :param sock:
        :param open_channel_callback:
        :param close_channel_callback:
        :type self.channels: list[(Channel, int)]
        :type self.transport: socket.socket
        """
        self.logger = logging.getLogger('tunnel')
        self.channels = []
        self.transport = sock
        self.transport_lock = threading.Lock()
        self.closed_channels = {}

        if open_channel_callback is None:
            self.open_channel_callback = lambda x: None
        else:
            self.open_channel_callback = open_channel_callback  # type: callable

        if close_channel_callback is None:
            self.close_channel_callback = lambda x: None
        else:
            self.close_channel_callback = close_channel_callback  # type: callable

        self.monitor_thread = threading.Thread(target=self._monitor, daemon=True)
        self.monitor_thread.start()

        signal.signal(signal.SIGINT, self.sigint_handler)
        signal.signal(signal.SIGQUIT, self.sigquit_handler)


    def __repr__(self):
        msg = '<Tunnel OpenChannels={} ClosedChannels={} BytesTX={} BytesRX={}>'
        return msg.format(
            len(self.channels),
            len(self.closed_channels),
            sum([c.tx for c, _ in self.channels] + [c.tx for _, c in self.closed_channels.items()]),
            sum([c.rx for c, _ in self.channels] + [c.rx for _, c in self.closed_channels.items()]),
        )

    def sigquit_handler(self, signum, frame):
        self.logger.debug('Caught SIGQUIT (if you want to exit, use CTRL-C!!')
        print(self)
        return

    def sigint_handler(self, signum, frame):
        self.close_tunnel()
        sys.exit(0)

    def wait(self):
        self.monitor_thread.join()

    @property
    def channel_id_map(self):
        return {x: y for x, y in self.channels}

    @property
    def id_channel_map(self):
        return {y: x for x, y in self.channels}

    def _close_channel_remote(self, channel_id):
        message = Message(b'', channel_id, msg_type=MessageType.CloseChannel)
        self.logger.debug('Sending request to close remote channel: {}'.format(channel_id))
        self.transport_lock.acquire()
        self.transport.sendall(message.serialize())
        self.transport_lock.release()

    def close_channel(self, channel_id, close_remote=False, exc=False):
        if channel_id in self.closed_channels:
            if close_remote:
                self._close_channel_remote(channel_id)
            return

        if channel_id not in self.id_channel_map:
            if exc:
                raise ValueError('Attempted to close channel that is not open')
            else:
                self.logger.debug('Attempted to close channel that is not open : {}'.format(channel_id))
                return
        channel = self.id_channel_map[channel_id]
        channel.close()
        try:
            self.channels.remove((channel, channel_id))
        except ValueError:
            self.logger.debug('Attempted to remove a channel not in the channel list')
        if close_remote:
            self._close_channel_remote(channel_id)
        self.close_channel_callback(channel)
        self.closed_channels[channel_id] = channel
        self.logger.debug('Closed a channel: {}'.format(channel))

    def close_tunnel(self):
        self.logger.info('Closing Tunnel: {}'.format(self))
        for channel, channel_id in self.channels:
            self.close_channel(channel_id, close_remote=True)
        self.transport.close()

    def _open_channel_remote(self, channel_id):
        message = Message(b'', channel_id, MessageType.OpenChannel)
        self.logger.debug('Sending request to open remote channel: {}'.format(channel_id))
        self.transport_lock.acquire()
        self.transport.sendall(message.serialize())
        self.transport_lock.release()

    def open_channel(self, channel_id, open_remote=False, exc=False):
        if channel_id in self.id_channel_map:
            self.logger.warn('Attempted to open an already open channel : {}'.format(self.id_channel_map[channel_id]))
            if exc:
                raise ValueError('Channel already opened')
            else:
                return self.id_channel_map[channel_id]
        channel = Channel(channel_id)
        self.channels.append((channel, channel_id))
        if open_remote:
            self._open_channel_remote(channel_id)
        self.open_channel_callback(channel)
        self.logger.debug('Opened a channel: {}'.format(channel))
        return channel

    def recv_message(self):
        """
        Receives an entire message from the tunnel transport socket
        :raises ValueError: When we fail to receive a complete Message header or body
        :return: A complete message received across the tunnel
        :rtype: Message
        """
        data = b''  # leave this, it's a small enough chunk the number of reallocations will be small
        while len(data) < Message.HDR_SIZE:
            _data = self.transport.recv(Message.HDR_SIZE - len(data))
            if not _data:
                break
            data += _data
        if len(data) != Message.HDR_SIZE:
            raise ValueError('Error encountered while receiving Message header')
        msg_type, channel_id, length = Message.parse_hdr(data)

        chunks = []
        received = 0
        while received < length:
            _data = self.transport.recv(length - received)
            if not _data:
                break
            chunks.append(_data)
            received += len(_data)
        if received != length:
            raise ValueError('Error encountered while receiving Message body')
        return Message(b''.join(chunks), channel_id, msg_type)

    def _monitor(self):
        while True:
            ignored_channels = []  # channels that were closed in this iteration

            read_fds = [channel.tunnel_interface for channel, channel_id in self.channels] + [self.transport]

            # Select for read on transport and on channels
            try:
                r, _, _ = select.select(read_fds, [], [], 1)
            except Exception as e:
                self.logger.debug('Error encountered while selecting on channels and transport: {}'.format(e))
                continue

            if not r:
                continue

            # If tunnel is ready, read all messages and send to appropriate channels
            if self.transport in r:
                # Receive a message
                try:
                    message = self.recv_message()
                except ValueError as e:
                    self.logger.critical('Error encountered while reading from transport: {}'.format(e))
                    sys.exit(1)

                self.logger.debug('Received a message: {}'.format(message))

                # Check if it's a ChannelClose message
                if message.msg_type == MessageType.CloseChannel:
                    self.close_channel(message.channel_id)
                    ignored_channels.append(message.channel_id)
                # Check if it's a ChannelOpen message
                elif message.msg_type == MessageType.OpenChannel:
                    self.open_channel(message.channel_id)
                # Check if it's a Data message
                elif message.msg_type == MessageType.Data:
                    channel = self.id_channel_map.get(message.channel_id)
                    if channel is None:
                        self.logger.debug('Received a message for an unknown channel, closing remote')
                        self.close_channel(message.channel_id, close_remote=True)
                    else:
                        channel.tunnel_interface.sendall(message.data)
                # Not implemented channel type
                else:
                    self.logger.warn('Non-implemented MessageType received: {}'.format(message.msg_type))

            # If channels ready, then read data, encapsulate in Message, and send over transport
            for tunnel_iface in r:
                if tunnel_iface == self.transport:
                    continue  # This was already handle above
                tiface_channel_map = {channel.tunnel_interface: channel for (channel, channel_id) in self.channels}
                channel = tiface_channel_map.get(tunnel_iface)
                if channel is None or channel.channel_id in ignored_channels:
                    continue  # Channel was closed or does not exist
                try:
                    data = tunnel_iface.recv(4096)
                except Exception as e:
                    self.logger.debug('Error encountered while receiving from {}: {}'.format(channel, e))
                    self.close_channel(channel.channel_id, close_remote=True)
                    continue
                if not data:
                    self.logger.debug('Received EOF from {}, closing channel remotely'.format(channel))
                    self.close_channel(channel.channel_id, close_remote=True)
                    continue

                message = Message(data, channel.channel_id, MessageType.Data)

                try:
                    self.transport_lock.acquire()
                    self.transport.sendall(message.serialize())
                    self.transport_lock.release()
                except:
                    self.logger.critical('Problem sending data over transport, tearing it down!')
                    os.kill(os.getpid(), signal.SIGINT)
                    return
        return

    def proxy_sock_channel(self, sock, channel, logger):
        """
        A convenience function to proxy data between a TCP socket and channel. Intended to be used by Tunnel clients,
        i.e. uses the client interface of the Channel rather than the tunnel interface
        :param socket.socket sock:
        :param Channel channel:
        :param logging.Logger logger:
        :rtype: None
        """

        def close_both():
            self.close_channel(channel.channel_id, close_remote=True)
            sock.close()

        logger.debug('Proxying data between socket and {}'.format(channel))

        while True:
            # Check if we should even still be running
            if (channel, channel.channel_id) not in self.channels:
                self.logger.debug('Cleaning up thread that handles {}'.format(channel))
                return

            # See if the channel / socket are ready to be read
            readfds = [channel, sock]
            try:
                r, _, _ = select.select(readfds, [], [], 1)
            except Exception as e:
                logger.debug('Error encountered while selecting on sockets: {}'.format(e))
                return
            if not r:
                continue

            # Handle reads from channel + writes to socket
            if channel in r:
                try:
                    data = channel.recv(4096)
                except Exception as e:
                    logger.error('Error receiving data from channel: {}'.format(e))
                    close_both()
                    return
                else:
                    if not data:
                        logger.debug('Received EOF from channel')
                        close_both()
                        return

                try:
                    sock.sendall(data)
                except Exception as e:
                    logger.error('Error encountered while sending data to remote socket: {}'.format(e))
                    close_both()
                    return

            # Handle reads from socket + writes to channel
            if sock in r:
                try:
                    data = sock.recv(4096)
                except Exception as e:
                    logger.debug('Error encountered while reading data from remote socket: {}'.format(e))
                    close_both()
                    return
                else:
                    if not data:
                        logger.debug('Received EOF from remote socket')
                        close_both()
                        return

                try:
                    channel.send(data)
                except Exception as e:
                    logger.error('Error sending to channel: {}'.format(e))
                    close_both()
                    return


class Server(object):
    def __init__(self, tunnel_port, socks_port, certfile=None, keyfile=None):
        """

        :param int tunnel_port:
        :param int socks_port:
        :type self.tunnel: Tunnel
        """
        self.logger = logging.getLogger('server')
        self.tunnel_port = tunnel_port
        self.tunnel_server = socket.socket()
        self.tunnel_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tunnel_server.bind(('', tunnel_port))
        self.tunnel_server.listen(1)

        self.socks_port = socks_port
        self.socks_server = socket.socket()
        self.socks_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socks_server.bind(('127.0.0.1', socks_port))
        self.socks_server.listen(100)

        self.tunnel = None
        self.channel_counter = counter(0)

        # Set up SSL if desired
        if certfile is not None:
            certfile = os.path.abspath(certfile)
        if keyfile is not None:
            keyfile = os.path.abspath(keyfile)
        if keyfile is None or certfile is None:
            self.logger.warn('A Certificate and/or Key was not given. Proceeding without SSL!')
        elif not os.path.isfile(certfile) or not os.path.isfile(keyfile):
            self.logger.error('Error locating SSL cert or key, bailing')
            sys.exit(-1)
        else:
            try:
                self.tunnel_server = ssl.wrap_socket(self.tunnel_server,
                                                     server_side=True,
                                                     certfile=certfile,
                                                     keyfile=keyfile)
            except Exception as e:
                self.logger.error('Error setting up SSL: {}'.format(e))
                sys.exit(-1)

        self.logger.debug('Server initialized')

    def _handle_channel(self, sock):
        """
        Create a channel in the Tunnel to accomodate new SOCKS client, and proxy data to/from the SOCKS client
        through the tunnel.
        :param socket.socket sock: A newly connect SOCKS client
        :return: nothing
        :rtype: None
        """
        host, port = sock.getpeername()[:2]
        try:
            channel = self.tunnel.open_channel(self.channel_counter.__next__(), open_remote=True, exc=True)
        except ValueError as e:
            self.logger.error('Error occurred while opening channel: {}'.format(e))
            sock.close()
            return

        self.tunnel.proxy_sock_channel(sock, channel, self.logger)
        self.logger.info('Terminating thread that handled {} <--> {}:{}'.format(channel, host, port))

    def run(self):
        self.logger.info('Listening for relay connections on {}:{}'.format('0.0.0.0', self.tunnel_port))
        client, addr = self.tunnel_server.accept()
        self.logger.info('Accepted relay client connection from: {}:{}'.format(*addr))
        self.tunnel = Tunnel(client)
        while True:
            socks_client, addr = self.socks_server.accept()
            self.logger.info('Accepted SOCKS client connection from {}:{}'.format(*addr))
            t = threading.Thread(target=self._handle_channel, args=(socks_client,), daemon=True)
            t.start()


class Socks5Proxy(object):
    @staticmethod
    def _remote_connect(remote_host, remote_port, sock, af=socket.AF_INET):
        """
        Connect to the final destination
        :param str remote_host: The host to connect to
        :param int remote_port: The port to connect on
        :param socket.socket sock: The tunnel from the SOCKS server that will be proxied to remote_host
        :param int af: Address family. Use either socket.AF_INET or socket.AF_INET6
        :return: The socket connected to the remote endpoint. An unconnected socket if connection fails
        :rtype: socket.socket
        """
        remote_socket = socket.socket(af, socket.SOCK_STREAM)

        # Get RFC1928 address type (minus domain)
        if af == socket.AF_INET:
            atyp = 1
            local_addr = ('0.0.0.0', 0)

        else:
            atyp = 4
            local_addr = ('::', 0)

        # Connect to the remote server
        try:
            remote_socket.connect((remote_host, remote_port))
        except Exception:
            # Connection failed
            reply = struct.pack('BBBB', 0x05, 0x05, 0x00, atyp)  # "SOCKSv5 | Connection refused"
        else:
            # Get the local socket and build the success reply message
            local_addr = remote_socket.getsockname()[:2]
            reply = struct.pack('BBBB', 0x05, 0x00, 0x00, atyp)  # "SOCKSv5 | succeeded"

        # Add local (proxy) address to SOCKSv5 reply message
        reply += socket.inet_pton(af, local_addr[0]) + struct.pack('!H', local_addr[1])
        sock.send(reply)

        return remote_socket

    @classmethod
    def new_connect(cls, sock):
        # Wait for authentication request from SOCKS client, reply with "no auth needed"
        sock.recv(4096)
        sock.sendall(struct.pack('BB', 0x05, 0x00))  # "SOCKSv5 | no authentication needed"

        # Wait for CONNECT request from client
        request_data = sock.recv(4096)
        if len(request_data) >= 10:
            ver, cmd, rsv, atyp = struct.unpack('BBBB', request_data[:4])
            if ver != 0x05 or cmd != 0x01:
                # Bad request; not SOCKSv5 or not CONNECT request
                sock.sendall(struct.pack('BBBB', 0x05, 0x01, 0x00, 0x00))
                sock.close()
                raise ValueError('Received invalid SOCKSv5 version or non-CONNECT message')
        else:
            # Partial CONNECT request received
            sock.sendall(struct.pack('BBBB', 0x05, 0x01, 0x00, 0x00))
            sock.close()
            raise ValueError('Received incomplete CONNECT request')

        # Parse the CONNECT request
        if atyp == 1:  # IPv4
            addr_type = socket.AF_INET
            addr = socket.inet_ntop(socket.AF_INET, request_data[4:8])
            port, = struct.unpack('!H', request_data[8:10])
        elif atyp == 3:  # Domain name, will be resolved by socket.connect API
            addr_type = socket.AF_INET
            length, = struct.unpack('B', request_data[4:5])
            addr = request_data[5:5 + length]
            port, = struct.unpack('!H', request_data[length + 5:length + 5 + 2])
        elif atyp == 4:  # IPv6
            addr_type = socket.AF_INET6
            addr = socket.inet_ntop(socket.AF_INET6, request_data[4:20])
            port, = struct.unpack('!H', request_data[20:22])
        else:
            # Received unknown address type
            sock.sendall(struct.pack('BBBB', 0x05, 0x08, 0x00, 0x00))
            sock.close()
            raise ValueError('Received unknown address type')

        # Connect to the remote endpoint
        addr = addr.decode()
        host = (addr, port)
        sock = cls._remote_connect(addr, port, sock, af=addr_type)
        return sock, host


class Relay(object):
    def __init__(self, connect_host, connect_port, no_ssl=False):
        """

        :param str connect_host:
        :param int connect_port:
        :type self.tunnel: Tunnel
        """
        self.logger = logging.getLogger('relay')
        self.no_ssl = no_ssl
        self.connect_server = (connect_host, connect_port)
        self.tunnel_sock = socket.socket()
        self.tunnel = None
        if not no_ssl:
            self.logger.info('SSL-wrapping client socket')
            self.tunnel_sock = ssl.wrap_socket(self.tunnel_sock)  # TODO : add certificate validation
        else:
            self.logger.warn('The proxy transport will not be encrypted with SSL!!')
        self.logger.debug('Completed initialization')

    def _handle_channel(self, channel):
        """
        Handle initial SOCKS protocol, and proxy data between remote endpoint and tunnel
        :param tunnel.Channel channel:
        :rtype: None
        """
        sock = None
        # Handle SOCKS setup protocol
        try:
            sock, addr = Socks5Proxy.new_connect(channel.client_interface)
        except ValueError as e:
            self.logger.debug('Error connecting to remote host: {}'.format(e))
            self.tunnel.close_channel(channel.channel_id, close_remote=True)
            return
        except Exception as e:
            self.logger.debug('Error encountered while processing SOCKS protocol: {}'.format(e))
            self.tunnel.close_channel(channel.channel_id, close_remote=True)
            try:
                if isinstance(sock, socket.socket):
                    sock.close()
            except:
                pass
            return

        self.logger.info('Connected {} <--> {}:{}'.format(channel, *addr))
        self.tunnel.proxy_sock_channel(sock, channel, self.logger)
        self.logger.info('Terminating thread that handled {} <--> {}:{}'.format(channel, *addr))

    def open_channel_callback(self, channel):
        """
        Channel was opened remotely. Start a new thread to handle SOCKS protocol and proxying data between
        remote host and tunnel.
        :param channel:
        :rtype: None
        """
        self.logger.debug('Spawning a thread to handle {}'.format(channel))
        t = threading.Thread(target=self._handle_channel, args=(channel,), daemon=True)
        t.start()

    def run(self):
        try:
            self.tunnel_sock.connect(self.connect_server)
        except Exception as e:
            self.logger.critical('Error connecting to server, bailing! [{}]'.format(e))
            return
        self.logger.info('Connected to server at {}:{}'.format(*self.tunnel_sock.getpeername()[:2]))
        self.tunnel = Tunnel(self.tunnel_sock, open_channel_callback=self.open_channel_callback)
        self.tunnel.wait()


def server_main(args):
    server = Server(args.tunnel_port, args.socks_port, args.cert, args.key)
    server.run()
    return


def relay_main(args):
    if args.connect is None:
        logging.debug('Connect string not provided on command-line, checking stdin...')
        r, _, _ = select.select([sys.stdin], [], [], 0)
        if sys.stdin not in r:
            logging.critical('Connect string not provided as argument or echoed in, exiting!')
            sys.exit(-1)
        args.connect = sys.stdin.read(256)

    if ':' not in args.connect:
        logging.critical('Make sure you specified your server in the HOST:PORT format')
        sys.exit(1)

    host, port = args.connect.split(':')
    port = int(port)

    relay = Relay(host, port, no_ssl=args.no_ssl)
    relay.run()
    return


def main():
    # Main parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', default=False, action='store_true', help='Enable debug mode')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Enable verbose mode')
    subparsers = parser.add_subparsers(help='Specify `server` mode or `relay` mode')

    # Server parser
    server_parser = subparsers.add_parser('server', description='Options for running in Server mode')
    server_parser.add_argument('-s', '--socks-port', type=int, default=1080,
                               help='The port to bind for the SOCKS server')
    server_parser.add_argument('-t', '--tunnel-port', type=int, default=4433,
                               help='The port to bind for the tunnel callback')
    server_parser.add_argument('--cert', default=None, help='The path to the SSL certificate file')
    server_parser.add_argument('--key', default=None, help='The path to the SSL key file')
    server_parser.set_defaults(main_function=server_main)

    # Relay parser
    relay_parser = subparsers.add_parser('relay', description='Options for running in Relay mode')
    relay_parser.add_argument('--connect', default=None, help='The socksychains server to connect to (i.e. host:port). '
                                                              'Alternatively, this can be piped in at runtime.')
    relay_parser.add_argument('--no-ssl', dest='no_ssl', default=False, action='store_true',
                              help='Disable SSL on tunnel to the server')
    relay_parser.set_defaults(main_function=relay_main)

    # Parse the arguments
    args = parser.parse_args()

    # Set logging level
    log_level = logging.WARNING
    if args.verbose:
        log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG

    logging.basicConfig(
        format='[%(asctime)s] %(levelname)8s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=log_level
    )

    # Run the desired functionality
    args.main_function(args)


if __name__ == '__main__':
    main()
