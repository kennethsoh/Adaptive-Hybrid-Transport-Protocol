import socket
import struct
import time
import logging
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Any, Tuple

import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from aioquic.quic.connection import QuicConnection
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    QuicEvent,
    StreamDataReceived,
    DatagramFrameReceived,
    ConnectionTerminated,
    HandshakeCompleted,
)
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import pull_quic_header, QuicProtocolVersion
from aioquic.buffer import Buffer

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s', datefmt='%H:%M:%S')

# Protocol Header
HEADER_FMT = "!B I d i"
HEADER_LEN = struct.calcsize(HEADER_FMT)

# Channel Types
class ChannelType(Enum):
    """
    RELIABLE = 0: Sent over QUIC streams (reliable, ordered)
    UNRELIABLE = 1: Sent over QUIC datagrams (unreliable, unordered)
    """
    RELIABLE = 0
    UNRELIABLE = 1

# ==============================================================
# Packet Class
# ==============================================================
@dataclass
class Packet:
    """
    Represents a network packet with header and payload.
    [ Channel Type (1B) | Seq No (4B) | Timestamp (8B) | Payload Length (4B) | Payload (variable) ]
    """
    channel_type: ChannelType
    seq_no: int
    timestamp: float
    payload: bytes

    def to_bytes(self) -> bytes:
        header = struct.pack(
            HEADER_FMT,
            self.channel_type.value,
            self.seq_no,
            self.timestamp,
            len(self.payload)
        )
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Packet':
        if len(data) < HEADER_LEN:
            raise ValueError(f"Data too short")
        
        ch_val, seq_no, ts, payload_len = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
        payload = data[HEADER_LEN:HEADER_LEN + payload_len]
        
        return cls(ChannelType(ch_val), seq_no, ts, payload)

# ==============================================================
# Metrics
# ==============================================================
@dataclass
class ChannelMetrics:
    packets_sent: int = 0
    packets_received: int = 0
    packets_delivered: int = 0
    packets_lost: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    total_retransmissions: int = 0
    unique_retransmissions: int = 0
    latency_samples: list = None
    jitter: float = 0.0

    # Reliable channel specific metrics
    pending_reliable: dict[int, float] = field(default_factory=dict)
    missed_packets: set[int] = field(default_factory=set)

    def __post_init__(self):
        self.latency_samples = []

    def record_latency(self, latency):
        """
        Jitter is the difference in latency between successive packets.
        Record latency sample and update jitter using EWMA, which 
        recursively updates the average with each new data point using the formula:
        J_new = J_old + (|D| - J_old) / 16

        Args:
            latency: Measured latency in seconds
        """
        if self.latency_samples:
            prev = self.latency_samples[-1]
            d = abs(latency - prev)
            self.jitter += (d - self.jitter) / 16.0
        self.latency_samples.append(latency)


# ==============================================================
# GameNetAPI Class
# ==============================================================
class GameNetAPI:
    """
    Wrapper around aioquic to provide simplified QUIC networking for reliable and unreliable channels.
    - Reliable channel: Sent over QUIC streams. Ordered delivery, retransmission, 
        and gap handling (out-of-order packets are buffered for up to value defined in self._rel_skip_timeout).
    - Unreliable channel: Sent over QUIC datagrams. No ordering or retransmission.

    Usage flow (server):
    api = GameNetAPI(is_server=True, host, port)
    api.generate_self_signed_cert()  # once, to create cert.pem and key
    api.start_server(certfile, keyfile)
    api.set_deliver_callback(callback)
    api.listen_for_incoming(duration)

    Usage flow (client):
    api = GameNetAPI(is_server=False, host, port)
    api.connect_to_server(server_host, server_port)
    api.set_deliver_callback(callback)
    api.send_reliable(payload) or api.send_unreliable(payload)
    api.process_events()
    api.close()
    
    """
    def __init__(self, is_server: bool, host: str, port: int):
        """
        Initialize the GameNetAPI instance.
        Creates a non-blocking UDP socket and prepares for QUIC connection.

        Args:
            is_server: True if server, False if client
            host: My Host IP address to bind/connect
            port: My Port number to bind/connect
        
        """
        self.is_server = is_server
        self.host = host
        self.port = port

        # Create a non-blocking UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False) 

        # Create QUIC connection object (set values later)
        self.quic: Optional[QuicConnection] = None
        self.peer_addr: Optional[Tuple[str, int]] = None
        self.config: Optional[QuicConfiguration] = None

        # Initial sequence number = 0 for both channels
        self._unrel_next_seq = 0
        self._rel_next_seq = 0

        # next reliable seq to deliver
        self._rel_expected_seq = 0    
        
        # out of order reliable packets
        self._rel_buffer: Dict[int, Packet] = {}

        # perf_counter deadline for current gap
        self._rel_gap_deadline: Optional[float] = None

        # timeout duration to skip missing reliable packets (seconds)
        self._rel_skip_timeout = 0.200                 

        # set of seen reliable seq numbers (for duplicate detection)
        self._seen_rel_seqs: set[int] = set()

        # callback function set to None initially
        self._deliver_callback =  None

        # Stream data buffer - used in _handle_event
        self.stream_data = {}

        # Metrics
        self.reliable_metrics = ChannelMetrics()
        self.unreliable_metrics = ChannelMetrics()

        # Logging 
        self.logger = logging.getLogger(f"H-QUIC-{'Server' if is_server else 'Client'}")
        self.qlogger = QuicLogger()

        # Set handshake complete flag
        self.handshake_complete = False 

        # Start time for metrics - to be started on handshake complete
        self._start_time = None

        # End time for metrics - to be set on connection termination
        self._end_time = None
        self._elapsed = None

    def set_deliver_callback(self, callback: Callable[[Packet, Tuple[str, int]], None]):
        """
        Set the callback function to be invoked when a packet is delivered.
        Basically tells the API what function to invoke once a packet is ready for the application layer.
        This means that the application does not need to poll for incoming packets, the API will push them up.

        This function is called in the handle_received_data() method after processing incoming packets.

        Args:
            callback: Function with signature (packet: Packet, addr: (str, int))
            (or None to clear the callback)
        """
        self._deliver_callback = callback

    def _unrel_alloc_seq(self) -> int:
        """
        Allocate a new sequence number for the unreliable channel.

        Returns:
            int: The allocated sequence number.
        """
        sequence = self._unrel_next_seq

        # Increment for next allocation
        self._unrel_next_seq += 1

        return sequence

    def _rel_alloc_seq(self) -> int:
        """
        Allocate a new sequence number for the unreliable channel.

        Returns:
            int: The allocated sequence number.
        """
        sequence = self._rel_next_seq

        # Increment for next allocation
        self._rel_next_seq += 1

        return sequence



    # ========================================================================
    # Certificate Generation Method
    # ========================================================================
    @staticmethod
    def generate_self_signed_cert():
        """
        Generate self-signed certificate for localhost
        This method creates a self-signed TLS certificate and private key,
        and saves them to 'cert.pem' and 'key.pem' files respectively.

        Required for QUIC server to perform TLS handshake.
        
        """

        # Generate private key
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)

        # Build subject and issuer
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Singapore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CS3103"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        
        # Write private key to file
        with open("key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate to file
        with open("cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        

    # ========================================================================
    # Server Methods
    # ========================================================================
    def start_server(self, certfile: str, keyfile: str):
        """
        Start the QUIC Server. 
        1. Binds the UDP socket.
        2. Creates QUIC configuration object, which defines the server behavior.
            - This configuration object is reused for all incoming connections to create QuicConnection instances.

        3. Loads the TLS certificate and key.

        Args:
            certfile: Path to the TLS certificate file.
            keyfile: Path to the TLS private key file. 
        """

        self.sock.bind((self.host, self.port))
        self.config = QuicConfiguration(
            is_client = False,
            alpn_protocols=["gamenet"],
            max_datagram_frame_size=65536,
            quic_logger=self.qlogger
        )

        # Load TLS certificate and key
        self.config.load_cert_chain(certfile, keyfile)

    def _start_server_connection(self, data: bytes, addr: Tuple[str, int]):
        """
        Kickstart a new QUIC connection object for a client session with the server.
        This method is invoked once per client, whenever a new connection begins.

        The server will:
        1. Parse the QUIC header to extract the destination connection IDs
            - We use aioquic's pull_quic_header function to return a QuicHeader object, which contains the destination connection ID. 
            - https://github.com/aiortc/aioquic/blob/main/src/aioquic/quic/packet.py#L181

        2. Create a new QuicConnection object using the QuicConfiguration.
            - This object will be used to manage the QUIC connection with the client.
            - It represents one active, stateful QUIC session using the blueprint from the QuicConfiguration object.

        3. Process the initial packet data to kickstart the handshake.

        Args:
            data: Initial packet data received from client.
            addr: Client address (IP, port) tuple.
        """
        # Parse the QUIC header to obtain the destination connection ID. 
        buffer = Buffer(data=data)
        header = pull_quic_header(buffer, host_cid_length=8) 
        dest_cid = header.destination_cid
        
        # Create a new QuicConnection object for this specific client connection.
        self.quic = QuicConnection(
            configuration=self.config, 
            original_destination_connection_id=dest_cid
        )
        
        self.peer_addr = addr

        # Process the initial packet data to kickstart the handshake.
        self.quic.receive_datagram(data, addr, now=time.time())
        self._flush_packets()

        self.logger.info(f"New connection from {addr}")

    # ========================================================================
    # Client Methods
    # ========================================================================
    def connect_to_server(self, server_host: str, server_port: int):
        """
        Connect to the QUIC server.
        Perform the QUIC handshake.

        Args:
            server_host: The hostname of the server.
            server_port: The port number of the server.

        """
        # Set peer (server) address
        self.peer_addr = (server_host, server_port)

        # Create QUIC configuration object for client
        config = QuicConfiguration(
            is_client = True,
            alpn_protocols=["gamenet"],
            max_datagram_frame_size=65536,
            quic_logger=self.qlogger
        )
        config.verify_mode = False  # skip certificate verification for self-signed certs

        # Create the QUIC Connection object using the configuration.
        self.quic = QuicConnection(configuration=config)

        # Initiate the connection (starts the TLS handshake)
        # This method can only be called for clients and a single time.
        self.quic.connect(self.peer_addr, now=time.time())

        self._flush_packets()

        # Wait for handshake to complete
        timeout = time.time() + 5.0
        while not self.handshake_complete and time.time() < timeout:
            self.process_events(timeout=0.1)
        if self.handshake_complete:
            self.logger.info("Handshake complete")
        else:
            raise TimeoutError("Handshake timed out")
    
    def drain_events(self, timeout=5.0):
        """
        Drain all pending events until there are no more reliable packets pending.
        This method ensures that all reliable packets have been processed before proceeding.
        Adds a timeout to prevent indefinite blocking.
        Args:
            timeout: Maximum time to wait (seconds)
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.reliable_metrics.pending_reliable and self.quic.get_timer() is None:
                break
            self.process_events(timeout=0.1)
            time.sleep(0.1)

    # ========================================================================
    # Core QUIC Event Loop Methods
    # ========================================================================

    def listen_for_incoming(self, duration: float = None):
        """
        This method runs a loop to continuously process incoming QUIC events.
        Each iteration processes incoming packets and handles QUIC events.

        For servers, this will handle multiple client connections.
        This method should not be called for clients, as clients typically manage their own event loop.
        
        1. Blocks on socket using recvfrom() until data arrives.

        2. Feeds the received datagram to the QUIC connection: self.quic.receive_datagram(data, addr, now=time.time()), 
            which parses the header, decrypts, and processes QUIC frames.

        3. Retrieves pending QUIC events (e.g., handshake complete, new stream data, connection close).

        4. Sends any queued datagrams that QUIC wants to transmit (ACKs, retransmissions, handshake messages).

        5. Calls handle_timer() to maintain loss detection and retransmission logic.

        
        Args:
            duration: How long to run (seconds), None = forever
        """
        start_time = time.time()
        
        try:
            while True:
                # Check duration, if specified
                if duration and (time.time() - start_time) >= duration:
                    break
                
                # Process QUIC events
                self.process_events(timeout=0.1)
                
        except KeyboardInterrupt:
            self.logger.info("Interrupted")

    def process_events(self, timeout: float = 0):
        """
        Process incoming QUIC events.
        1. Receives data from the UDP socket.
        2. Feeds inbound to quic.receive_datagram().
        3. Drains all quic.next_event() calls to _handle_event().
        4. Sends any pending outbound with _flush_packets().
        5. Calls _maybe_skip_reliable_gap() to handle reliable packet gaps.

        Args:
            timeout: Time in seconds to wait for incoming data.
        """

        self.sock.settimeout(timeout)

        try:
            # Receive data from socket
            data, addr = self.sock.recvfrom(65536)

            # If server and no existing connection, start a new one
            if self.is_server and self.quic is None:
                self._start_server_connection(data, addr)
            elif self.quic:
                self.quic.receive_datagram(data, addr, now=time.time())

            if self.quic:
                while True:
                    event = self.quic.next_event()
                    if event is None:
                        break

                    self._handle_event(event)
            
            # Send any responses
            self._flush_packets()
            self._maybe_skip_reliable_gap()

        except socket.timeout:
            # No data received within timeout
            if self.quic:
                timer = self.quic.get_timer()
                if timer is not None and timer <= time.time():
                    self.quic.handle_timer(time.time())
                    self._flush_packets()
                    self._maybe_skip_reliable_gap()

        except TimeoutError:
            pass
        except BlockingIOError:
            pass
        except Exception as e:
            self.logger.error(f"Error receiving data in process_events: {e}")

    def _handle_event(self, event: QuicEvent):
        """
        Handle a single QUIC event.

        Decides what to do based on event type (handshake complete, stream data received, datagram received, connection terminated).
        - If is handshake complete, sets flag, starts timer.
        - If is stream data received, buffers data and calls _handle_received_data() when end_stream is reached. (this assumes one msg per stream)
        - If is datagram received, calls _handle_received_data() directly.
        - If is connection terminated, logs the reason.

        Args:
            event: QUIC event to handle
        
        """
        if isinstance(event, HandshakeCompleted):
            self.handshake_complete = True
            self._start_time = time.perf_counter()
            self.logger.info("Handshake completed")
        
        elif isinstance(event, StreamDataReceived):
            # For reliable channel data

            # Get stream ID from event
            stream_id = event.stream_id
            
            if stream_id not in self.stream_data:
                self.stream_data[stream_id] = b""
            
            self.stream_data[stream_id] += event.data
            
            if event.end_stream:
                data = self.stream_data.pop(stream_id)
                self._handle_received_data(data)
        
        elif isinstance(event, DatagramFrameReceived):
            # For unreliable channel data
            self._handle_received_data(event.data)
        
        elif isinstance(event, ConnectionTerminated):
            self._end_time = time.perf_counter()
            self._elapsed = self._end_time - self._start_time if self._start_time else 0
            self.logger.info(f"Connection terminated (error={event.error_code}, reason={event.reason_phrase})")


    def _handle_received_data(self, data: bytes):
        """
        Parse one framed message and update metrics, then hand to the application.
        Converts bytes to Packet object, computes latency, updates metrics, and calls the deliver callback.

        """
        try:
            packet = Packet.from_bytes(data)
            latency = time.time() - packet.timestamp

            if packet.channel_type == ChannelType.RELIABLE:
                # de-dup guard: if client accidentally re-sends the same seq
                if packet.seq_no in self._seen_rel_seqs:
                    return
                self._seen_rel_seqs.add(packet.seq_no)
                self._reliable_receive(packet, latency)
            else:
                self._deliver_unreliable_to_app(packet, latency)

        except Exception as e:
            self.logger.error(f"Error handling data: {e}")

    def _reliable_receive(self, packet: Packet, latency: float) -> None:
        """
        Enforce in order delivery for reliable packets.
        If there is a gap, buffer out of order packets and start a 200 ms timer.
        When the timer expires, skip the missing seq and release buffered packets.

        Args:
            packet: Received Packet object.
            latency: Measured latency in seconds.

        Returns:
            None
        """
        seq = packet.seq_no

        # If exactly the expected seq
        if seq == self._rel_expected_seq:
            self._deliver_reliable_to_app(packet, latency)
            self._rel_expected_seq += 1

            # Release any buffered contiguous packets
            while self._rel_expected_seq in self._rel_buffer:
                pkt = self._rel_buffer.pop(self._rel_expected_seq)
                lat = time.time() - pkt.timestamp
                self._deliver_reliable_to_app(pkt, lat)
                self._rel_expected_seq += 1

            # No gap remains
            self._rel_gap_deadline = None
            return

        # If seq less than expected, duplicate or late packet - discard
        if seq < self._rel_expected_seq:
            return

        # If seq greater than expected, buffer it
        self._rel_buffer[seq] = packet

        # If this is the first time we discover a gap, start the 200 ms deadline
        if self._rel_gap_deadline is None:
            self._rel_gap_deadline = time.perf_counter() + self._rel_skip_timeout

    def _deliver_reliable_to_app(self, packet: Packet, latency: float) -> None:
        """
        Update reliable metrics and forward to application callback.
        Called when a reliable packet is ready to be delivered to the application layer, 
        when it is in order, or when a gap is skipped.

        Args:
            packet: Packet to deliver.
            latency: Measured latency in seconds.
        Returns:
            None
        """
        try:
            # Unique Stats Packet from Sender
            stats = json.loads(packet.payload.decode('utf-8'))
            if isinstance(stats, dict) and "total_unreliable_sent" in stats:
                count = int(stats["total_unreliable_sent"])
                self.unreliable_metrics.packets_sent = count
                self.logger.info(f"[STATS] Received Unreliable Sender stats: total_unreliable_sent={count}")
        except Exception:
            pass

        if packet.seq_no in self.reliable_metrics.missed_packets:
            self.logger.info(
                f"[LATE-SKIPPED] {'RELIABLE' if packet.channel_type.value == 0 else 'UNRELIABLE'} seq={packet.seq_no} latency={latency*1000:.2f}ms "
                f"jitter={self.reliable_metrics.jitter*1000:.2f}ms timestamp={packet.timestamp:.3f}"
            )
            return 

        # Update reliable metrics
        self.reliable_metrics.packets_received += 1
        self.reliable_metrics.bytes_received += HEADER_LEN + len(packet.payload)
        self.reliable_metrics.record_latency(latency)
        self.reliable_metrics.pending_reliable.pop(packet.seq_no, None)

        # Deliver to application
        self._deliver_packet(packet, latency)

    def _deliver_unreliable_to_app(self, packet: Packet, latency: float) -> None:
        """
        Update unreliable metrics and forward to application callback.
        Called when an unreliable packet is received, no need to check order.

        Args:
            packet: Received Packet object.
            latency: Measured latency in seconds.
        Returns:
            None
        """
        # Update unreliable metrics
        self.unreliable_metrics.packets_received += 1
        self.unreliable_metrics.bytes_received += HEADER_LEN + len(packet.payload)
        self.unreliable_metrics.record_latency(latency)

        # Deliver to application
        self._deliver_packet(packet, latency)

    def _maybe_skip_reliable_gap(self) -> None:
        """
        If we are waiting on a missing reliable seq and its deadline has passed,
        mark it skipped and release any buffered packets that now become in order.
        This ensures that ordering is maintained, while preventing indefinite blocking on lost packets.
        There is no HOL blocking as each packet uses its own QUIC stream.

        """
        if self._rel_gap_deadline is None:
            return
        if time.perf_counter() < self._rel_gap_deadline:
            return

        missed = self._rel_expected_seq
        self.logger.info(f"[SKIP] RELIABLE seq={missed} after {int(self._rel_skip_timeout * 1000)} ms")

        self.reliable_metrics.missed_packets.add(missed)
        self.reliable_metrics.pending_reliable.pop(missed, None)

        # Advance past the missing one
        self._rel_expected_seq += 1
        self._rel_gap_deadline = None

        # Deliver any buffered packets that are now contiguous
        while self._rel_expected_seq in self._rel_buffer:
            pkt = self._rel_buffer.pop(self._rel_expected_seq)
            lat = time.time() - pkt.timestamp
            self._deliver_reliable_to_app(pkt, lat)
            self._rel_expected_seq += 1

        # If a new gap remains with higher seq buffered, start another timer
        if any(s > self._rel_expected_seq for s in self._rel_buffer.keys()):
            self._rel_gap_deadline = time.perf_counter() + self._rel_skip_timeout



    def _deliver_packet(self, packet: Packet, latency: float):
        """
        Deliver packet to application layer via callback.
        This method is called when a packet (reliable or unreliable) is ready to be handed to the application layer.

        Args:
            packet: Packet to deliver.
            latency: Measured latency in seconds.   

        """
        self.logger.info(
            f"[DELIVER] {'RELIABLE' if packet.channel_type.value == 0 else 'UNRELIABLE'} seq={packet.seq_no} latency={latency*1000:.2f}ms "
            f"jitter={self.reliable_metrics.jitter*1000:.2f}ms timestamp={packet.timestamp:.3f}"
        )
        if self._deliver_callback:
            self._deliver_callback(packet, self.peer_addr)

    def _flush_packets(self):
        """
        Send any UDP datagrams that aioquic currently wants to transmit.
        Asks quic.datagrams_to_send() for pending datagrams and sends them via the UDP socket.
        This includes handshake messages, ACKs, retransmissions, STREAM frames, DATAGRAM frames, etc.


        """
        if not self.quic or not self.peer_addr:
            return

        # Normal QUIC datagrams
        for data, addr in self.quic.datagrams_to_send(now=time.time()):
            self.sock.sendto(data, addr)

    # ========================================================================
    # Sending Methods
    # ========================================================================
    def send_reliable(self, payload: bytes) -> int:
        """
        Send a reliable packet via QUIC stream.

        Args:
            payload: Bytes payload to send.

        Returns:
            Sequence number of the sent packet.
        
        """
        if not self.quic or not self.handshake_complete:
            raise RuntimeError("Not connected")

        # Obtain a sequence number
        seq = self._rel_alloc_seq()
        self.reliable_metrics.pending_reliable[seq] = time.time()

        # Set the packet type to RELIABLE and create Packet object with timestamp and payload
        packet = Packet(ChannelType.RELIABLE, seq, time.time(), payload)

        # Convert the Packet to bytes for transmission
        data = packet.to_bytes()

        self.reliable_metrics.packets_sent += 1
        self.reliable_metrics.bytes_sent += len(data)
        # self.reliable_manager.track_sent(packet)

        # Send via QUIC stream
        stream_id = self.quic.get_next_available_stream_id()
        self.quic.send_stream_data(stream_id, data, end_stream=True)

        # Flush out to network
        self._flush_packets()
        self.logger.info(f"[SEND] RELIABLE seq={seq} stream={stream_id} size={len(payload)}B")

        return seq

    def send_unreliable(self, payload: bytes) -> int:
        """
        Sends a (unreliable) packet via QUIC datagram.
        Does not use streams as they are reliable by default. 

        The traditional method (in RFC 9000) is to use streams and then reset_stream to cancel retransmissions,
        but RFC 9221 introduced datagrams as a primitive for unordered, unreliable delivery.
        This is more efficient and better suited for our use case.

        The packet is not acknowledged, retransmitted or ordered.

        Args:
            payload: Bytes payload to send.
        Returns:
            Sequence number of the sent packet.

        """
        if not self.quic or not self.handshake_complete:
            raise RuntimeError("Not connected")
        
        # Obtain a sequence number
        seq = self._unrel_alloc_seq()

        # Set the packet type to UNRELIABLE and create Packet object with timestamp and payload
        packet = Packet(ChannelType.UNRELIABLE, seq, time.time(), payload)

        # Convert the Packet to bytes for transmission
        data = packet.to_bytes()
        
        self.unreliable_metrics.packets_sent += 1
        self.unreliable_metrics.bytes_sent += len(data)
        
        # Send via QUIC datagram
        self.quic.send_datagram_frame(data)
        
        # Flush packets
        self._flush_packets()
        
        self.logger.info(f"[SEND] UNRELIABLE seq={seq} size={len(payload)}B")
        return seq

    # ========================================================================
    # Metrics Reporting
    # ========================================================================

    def count_retransmissions_from_qlogger(self):
        """
        Count retransmissions from the Quic-Logger (QLOG) data.
        This is done by parsing the QLOG traces for "transport:packet_sent" events,
        looking for stream frames, and checking for duplicate (stream_id, offset, length) tuples.
        A duplicate indicates a retransmission.

        Returns:
            unique_retrans: Number of unique retransmitted stream frames.
            total_retrans: Total number of retransmissions (including duplicates).
        """
        qlog_dict = self.qlogger.to_dict()
        traces = qlog_dict.get("traces", [])
        if not traces:
            return {}, 0

        events = traces[0].get("events", [])

        seen = {}
        retrans = {}

        for ev in events:
            # only packet_sent events
            if ev.get("name") != "transport:packet_sent":
                continue

            data = ev.get("data", {})
            header = data.get("header", {})

            # only 1RTT packets
            if header.get("packet_type") != "1RTT":
                continue

            # look for stream frames only
            for fr in data.get("frames", []):
                if fr.get("frame_type") != "stream":
                    continue

                stream_id = fr["stream_id"]
                offset = fr.get("offset")
                length = fr.get("length")

                key = (stream_id, offset, length)

                if key in seen:
                    # increments retrans count
                    retrans[key] = retrans.get(key, 0) + 1
                else:
                    seen[key] = 1

        total_retrans = sum(retrans.values())
        unique_retrans = len(retrans)
        return unique_retrans, total_retrans


    def report_results(self):
        """
        Compute and log all performance metrics after test duration.
        
        """
        # Calculate duration: use actual elapsed time or time since start
        if self._elapsed:
            duration = self._elapsed
        elif self._start_time:
            duration = time.perf_counter() - self._start_time
        else:
            duration = 0

        # Save qlog to file for offline analysis
        with open(f"{'receiver' if self.is_server else 'sender'}.qlog", "w") as f:
            import json
            json.dump(self.qlogger.to_dict(), f)

        unique_retrans, total_retrans, retrans_dict = self.count_retransmissions_from_qlogger()
        self.reliable_metrics.total_retransmissions = total_retrans
        self.reliable_metrics.unique_retransmissions = unique_retrans

        formatted_retrans = {
            f"Stream {key[0]}": count
            for key, count in retrans_dict.items()
        }

        # Printing results
        role_label = "SENDER" if not self.is_server else "RECEIVER"
        self.logger.info(f"\n================ {role_label} METRICS ================ \n")
        self.logger.info(f"Duration: {duration:.3f}s\n")
        
        for label, m in [("RELIABLE", self.reliable_metrics), ("UNRELIABLE", self.unreliable_metrics)]:

            avg_lat = (sum(m.latency_samples) / len(m.latency_samples)) if m.latency_samples else 0

            self.logger.info(f"--- {label} CHANNEL ---")
            if role_label == "SENDER":
                self.logger.info(f"Packets Sent: {m.packets_sent}")
            elif role_label == "RECEIVER":
                self.logger.info(f"Packets Received (in-time): {m.packets_received}")
            
            if not self.is_server:
                # SENDER view: show retransmissions
                throughput = m.bytes_sent / duration if duration > 0 else 0
                if label == "RELIABLE":
                    self.logger.info(f"Total Retransmissions: {m.total_retransmissions}")
                    self.logger.info(f"Unique Retransmissions: {m.unique_retransmissions}")
                    if formatted_retrans:
                        self.logger.info(f"Retransmissions Breakdown by Stream: {formatted_retrans}")
            else:
                # RECEIVER view: show app-layer delivery effects
                throughput = m.bytes_received / duration if duration > 0 else 0

                total_expected = 0
                if label == "RELIABLE":
                    total_expected = (m.packets_received + len(m.missed_packets))
                else:
                    # Unreliable - If not Default to the Unfixed PDR calculation
                    total_expected = m.packets_sent if m.packets_sent > 0 else (m.packets_received + len(m.missed_packets))

                pdr = (m.packets_received / total_expected * 100) if total_expected > 0 else 0

                if label == "RELIABLE":
                    self.logger.info(f"Skipped (timed-out ({self._rel_skip_timeout * 1000}ms)): {len(m.missed_packets)}")
                    self.logger.info(f"Late Arrivals (useless): {len(m.late_arrivals)}")
                
                self.logger.info(f"PDR (App Pkt Delivery Ratio): {pdr:.2f}%")
                self.logger.info(f"Average Latency: {avg_lat * 1000:.2f} ms")
                self.logger.info(f"Jitter: {m.jitter * 1000:.2f} ms")

            self.logger.info(f"Throughput: {throughput:.2f} B/s\n")

    def close(self):
        """
        Close the UDP socket and QUIC connection.
        This method should not be called before report_results() to ensure all metrics are captured.
        """
        if self.quic:
            self.quic.close()
            self._flush_packets()
        self.sock.close()   
        self.logger.info("Connection closed")
    