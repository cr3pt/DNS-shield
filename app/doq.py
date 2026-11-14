# SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-Commons-Clause
# See the LICENSE file in the project root for full license terms.

"""DNS-over-QUIC (RFC 9250): forwarding to `quic://` upstreams, and an
optional listener so clients can query DNS-shield over QUIC.

DoQ sends each query on its own QUIC stream as a 2-byte length plus the DNS
message, with the message ID set to 0 (the stream identifies the query). One
QUIC connection carries any number of concurrent queries, so connections to
an upstream are kept open and shared.

aioquic is asyncio-based while the resolver is threaded: everything QUIC runs
on one event loop in a background thread, and the threaded side hands work to
it (forward()) or gets called from it (the server, via run_in_executor)."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, QuicEvent

logger = logging.getLogger("dnsshield.doq")

ALPN = ["doq"]
DEFAULT_PORT = 853
# Close a connection nobody has used for this long (both directions).
_IDLE_TIMEOUT = 30.0
_MAX_MESSAGE = 65535

_loop: asyncio.AbstractEventLoop | None = None
_loop_lock = threading.Lock()


def _event_loop() -> asyncio.AbstractEventLoop:
    """The background event loop all QUIC traffic runs on (started on first use)."""
    global _loop
    with _loop_lock:
        if _loop is None:
            loop = asyncio.new_event_loop()
            threading.Thread(target=loop.run_forever, name="doq-loop", daemon=True).start()
            _loop = loop
        return _loop


class _Protocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.terminated = False

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self.terminated = True
        super().quic_event_received(event)


def _with_zero_id(message: bytes) -> bytes:
    return b"\x00\x00" + message[2:]


async def _exchange(protocol: _Protocol, query: bytes) -> bytes:
    reader, writer = await protocol.create_stream()
    writer.write(struct.pack("!H", len(query)) + query)
    writer.write_eof()
    data = await reader.read(_MAX_MESSAGE + 2)
    if len(data) < 2:
        raise ConnectionError("DoQ stream closed without an answer")
    length = struct.unpack("!H", data[:2])[0]
    if len(data) < 2 + length:
        raise ConnectionError("DoQ answer truncated")
    return data[2 : 2 + length]


# ---------------------------------------------------------------- client side


async def _open_connection(host: str, port: int, configuration: QuicConfiguration):
    """Like aioquic's connect(), minus its IPv6 dual-stack socket - which
    fails outright where IPv6 is disabled, as in many Docker setups. The
    socket's family follows the address the upstream resolves to."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    family, _type, _proto, _name, addr = infos[0]
    connection = QuicConnection(configuration=configuration)
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _Protocol(connection), family=family, local_addr=("::" if family == socket.AF_INET6 else "0.0.0.0", 0)
    )
    try:
        protocol.connect(addr)
        await protocol.wait_connected()
    except BaseException:
        transport.close()
        raise
    return protocol, transport


class _Upstream:
    """One shared connection to a DoQ upstream, reopened when it closes."""

    def __init__(self, host: str, port: int, configure: Callable[[QuicConfiguration], None] | None = None):
        self.host, self.port = host, port
        self._configure = configure
        self._protocol: _Protocol | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._connecting: asyncio.Lock | None = None

    async def _connection(self) -> _Protocol:
        if self._connecting is None:
            self._connecting = asyncio.Lock()
        async with self._connecting:
            if self._protocol is not None and not self._protocol.terminated:
                return self._protocol
            await self._close()
            configuration = QuicConfiguration(
                alpn_protocols=ALPN, is_client=True, server_name=self.host, idle_timeout=_IDLE_TIMEOUT
            )
            if self._configure is not None:
                self._configure(configuration)
            self._protocol, self._transport = await _open_connection(self.host, self.port, configuration)
            return self._protocol

    async def _close(self) -> None:
        protocol, transport = self._protocol, self._transport
        self._protocol = self._transport = None
        if protocol is not None:
            try:
                protocol.close()
                await asyncio.wait_for(protocol.wait_closed(), 1.0)
            except Exception:
                pass
        if transport is not None:
            transport.close()

    async def query(self, message: bytes) -> bytes:
        for attempt in range(2):
            protocol = await self._connection()
            try:
                return await _exchange(protocol, message)
            except (ConnectionError, OSError):
                # The connection died under us (idle timeout on the server's
                # side, network change): once more on a fresh one.
                if attempt:
                    raise
                protocol.terminated = True
        raise AssertionError("unreachable")


_upstreams: dict[tuple[str, int], _Upstream] = {}
_upstreams_lock = threading.Lock()
# Tests point this at a context that trusts their own certificate.
configure_client: Callable[[QuicConfiguration], None] | None = None


def forward(data: bytes, host: str, port: int, timeout: float) -> bytes:
    """Send one DNS query (wire format) to a DoQ upstream and return the answer,
    with the caller's message ID put back."""
    if len(data) < 12:
        raise ValueError("not a DNS message")
    with _upstreams_lock:
        upstream = _upstreams.get((host, port))
        if upstream is None:
            upstream = _upstreams[(host, port)] = _Upstream(host, port, configure_client)
    future = asyncio.run_coroutine_threadsafe(
        asyncio.wait_for(upstream.query(_with_zero_id(data)), timeout), _event_loop()
    )
    try:
        answer = future.result(timeout + 1)
    except TimeoutError:
        future.cancel()
        raise
    if len(answer) < 12:
        raise ConnectionError("DoQ answer too short")
    return data[:2] + answer[2:]


def reset_connections() -> None:
    """Forget every upstream connection (tests; config changes don't need it)."""
    with _upstreams_lock:
        upstreams = list(_upstreams.values())
        _upstreams.clear()
    for upstream in upstreams:
        asyncio.run_coroutine_threadsafe(upstream._close(), _event_loop())


# ---------------------------------------------------------------- server side


class _Handler:
    """What the resolver expects as its request handler: the client's address."""

    __slots__ = ("client_address",)
    encrypted_transport = True

    def __init__(self, client_address) -> None:
        self.client_address = client_address


class DoQServer:
    def __init__(self, server, executor: ThreadPoolExecutor) -> None:
        self._server = server
        self._executor = executor

    def stop(self) -> None:
        _event_loop().call_soon_threadsafe(self._server.close)
        self._executor.shutdown(wait=False, cancel_futures=True)


def start_server(resolver, cert_path, key_path, address: str = "0.0.0.0", port: int = DEFAULT_PORT, threads: int = 16):
    """Answer DoQ queries with the given resolver (the same FilteringResolver
    that serves plain DNS, so filtering, caching and logging all apply)."""
    from dnslib import RCODE, DNSRecord

    configuration = QuicConfiguration(alpn_protocols=ALPN, is_client=False, idle_timeout=_IDLE_TIMEOUT)
    configuration.load_cert_chain(str(cert_path), str(key_path))
    executor = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="doq-request")
    loop = _event_loop()

    def _resolve(message: bytes, client_address) -> bytes:
        request = DNSRecord.parse(message)
        try:
            return resolver.resolve(request, _Handler(client_address)).pack()
        except Exception:
            logger.exception("DoQ query from %s failed", client_address[0])
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply.pack()

    def _stream_handler_for(protocol: QuicConnectionProtocol):
        def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            loop.create_task(_answer(protocol, reader, writer))

        return handle

    async def _answer(protocol, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readexactly(2)
            message = await reader.readexactly(struct.unpack("!H", head)[0])
            peer = protocol._quic._network_paths[0].addr if protocol._quic._network_paths else ("?", 0)
            answer = await loop.run_in_executor(executor, _resolve, message, (peer[0], peer[1]))
            answer = _with_zero_id(answer)
            writer.write(struct.pack("!H", len(answer)) + answer)
            writer.write_eof()
        except Exception as exc:
            logger.debug("DoQ stream failed: %s", exc)
            try:
                writer.write_eof()
            except Exception:
                pass

    class _ServerProtocol(_Protocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._stream_handler = _stream_handler_for(self)

    async def _serve():
        return await serve(address, port, configuration=configuration, create_protocol=_ServerProtocol)

    server = asyncio.run_coroutine_threadsafe(_serve(), loop).result(10)
    logger.info("DoQ server listening on %s:%d (udp, quic)", address, port)
    return DoQServer(server, executor)
