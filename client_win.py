#!/usr/bin/env python3
"""
UDP File Transfer - Client

Send or receive files via UDP hole punching with sliding window protocol.
"""

import asyncio
import socket
import json
import time
import logging
import struct
import hashlib
import zlib
import os
import sys
from typing import Optional, Tuple, Dict, Set
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

Address = Tuple[str, int]

# Protocol constants
CHUNK_SIZE = 1400  # MTU-safe
WINDOW_SIZE = 256  # 256 chunks = 350 KB in flight (increased for performance)
PUNCH_DURATION = 20.0
PUNCH_RATE = 15.0
SOCKET_BUFFER_SIZE = 4 * 1024 * 1024  # 4 MB

# Message types (100+ to avoid collision with punch packets)
MSG_READY = 100
MSG_FILE_INFO = 101
MSG_FILE_INFO_ACK = 102
MSG_CHUNK = 103
MSG_ACK = 104
MSG_DONE = 105
MSG_FINAL_ACK = 106
MSG_ERROR = 107


class ProgressBar:
    """Display progress with speed and ETA"""
    
    def __init__(self, total_bytes: int, filename: str):
        self.total_bytes = total_bytes
        self.filename = filename
        self.transferred = 0
        self.start_time = time.time()
        self.last_update = 0
    
    def update(self, bytes_transferred: int):
        """Update progress"""
        self.transferred = bytes_transferred
        current_time = time.time()
        
        # Update every 0.2 seconds
        if current_time - self.last_update < 0.2:
            return
        
        self.last_update = current_time
        self.display()
    
    def display(self):
        """Display progress bar"""
        if self.total_bytes == 0:
            return
        
        percent = (self.transferred / self.total_bytes) * 100
        elapsed = time.time() - self.start_time
        
        if elapsed > 0 and self.transferred > 0:
            speed = self.transferred / elapsed  # bytes/sec
            remaining = self.total_bytes - self.transferred
            eta_seconds = remaining / speed if speed > 0 else 0
        else:
            speed = 0
            eta_seconds = 0
        
        # Format speed
        if speed > 1024 * 1024:
            speed_str = f"{speed / (1024 * 1024):.1f} MB/s"
        elif speed > 1024:
            speed_str = f"{speed / 1024:.1f} KB/s"
        else:
            speed_str = f"{speed:.0f} B/s"
        
        # Format ETA
        eta_m, eta_s = divmod(int(eta_seconds), 60)
        eta_h, eta_m = divmod(eta_m, 60)
        if eta_h > 0:
            eta_str = f"{eta_h:02d}:{eta_m:02d}:{eta_s:02d}"
        else:
            eta_str = f"{eta_m:02d}:{eta_s:02d}"
        
        # Progress bar
        bar_width = 40
        filled = int(bar_width * percent / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        
        # Size
        mb_transferred = self.transferred / (1024 * 1024)
        mb_total = self.total_bytes / (1024 * 1024)
        
        print(f"\r{self.filename}: [{bar}] {percent:5.1f}% | "
              f"{mb_transferred:.1f}/{mb_total:.1f} MB | {speed_str} | ETA: {eta_str}",
              end='', flush=True)
    
    def finish(self):
        """Mark as complete"""
        self.transferred = self.total_bytes
        self.display()
        print()  # New line


class FileTransferClient:
    """UDP File Transfer Client"""
    
    def __init__(self, server_addr: Address, mode: str, 
                 file_path: Optional[str] = None, code: Optional[str] = None):
        self.server_addr = server_addr
        self.mode = mode  # 'send' or 'receive'
        self.file_path = file_path
        self.code = code
        
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._connected = False
        self._peer_addr: Optional[Address] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        
        # Transfer state
        self.file_size = 0
        self.file_name = ""
        self.file_sha256 = ""
        self.chunks: Dict[int, bytes] = {}
        self.total_chunks = 0
        self.progress: Optional[ProgressBar] = None
        
        # Sender state
        self.window_start = 0
        self.acked_chunks: Set[int] = set()
        self.send_times: Dict[int, float] = {}
        self.peer_ready = False
        self.file_info_acked = False
        self.final_ack_received = False
        self.peer_received_chunks: Set[int] = set()
        
        # Receiver state
        self.received_chunks: Set[int] = set()
        self.last_ack_time = 0
        
        # Inactivity tracking
        self.last_activity = time.time()
        self.inactivity_timeout = 60  # seconds
    
    def _recv_blocking(self):
        """Blocking receive with timeout - works on Windows and Linux"""
        try:
            self._sock.settimeout(0.5)
            return self._sock.recvfrom(65535)
        except socket.timeout:
            return None, None
        except:
            return None, None
    
    def _send_blocking(self, data: bytes, addr: Address):
        """Blocking send - works on Windows and Linux"""
        try:
            self._sock.sendto(data, addr)
        except:
            pass
    
    async def _send(self, data: bytes, addr: Address):
        """Async send wrapper - uses executor for Windows compatibility"""
        await self._loop.run_in_executor(None, self._send_blocking, data, addr)
    
    async def start(self):
        """Start the client"""
        self._loop = asyncio.get_event_loop()
        self._running = True
        
        # Create socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
        # Windows: Keep socket blocking, use settimeout in recv_blocking
        self._sock.bind(('0.0.0.0', 0))
        
        local_port = self._sock.getsockname()[1]
        logger.info(f"Bound to local port {local_port}")
        
        # Start tasks
        recv_task = asyncio.create_task(self._receive_loop())
        inactivity_task = asyncio.create_task(self._inactivity_check())
        
        try:
            if self.mode == 'receive':
                await self._run_receiver()
            else:
                await self._run_sender()
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            recv_task.cancel()
            inactivity_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass
            try:
                await inactivity_task
            except asyncio.CancelledError:
                pass
            self._sock.close()
    
    async def _run_receiver(self):
        """Run as receiver"""
        logger.info("Running in RECEIVE mode")
        logger.info("Requesting transfer code from server...")
        
        # Request code from server
        msg = json.dumps({"type": "request_code"}).encode('utf-8')
        await self._send(msg, self.server_addr)
        
        # Wait for connection
        while self._running and not self._connected:
            await asyncio.sleep(0.1)
        
        if not self._running:
            return
        
        logger.info("✅ Connected! Sending READY signal...")
        
        # Send READY to sender - multiple times for reliability
        ready_msg = struct.pack('!B', MSG_READY)
        for _ in range(3):
            await self._send(ready_msg, self._peer_addr)
            await asyncio.sleep(0.1)
        
        logger.info("READY signal sent! Waiting for file info...")
        
        # Wait for transfer to complete
        while self._running:
            await asyncio.sleep(1)
    
    async def _run_sender(self):
        """Run as sender"""
        if not self.file_path or not os.path.exists(self.file_path):
            logger.error(f"File not found: {self.file_path}")
            return
        
        if not self.code:
            logger.error("Code required for sender mode")
            return
        
        logger.info(f"Running in SEND mode")
        logger.info(f"File: {self.file_path}")
        logger.info(f"Code: {self.code}")
        
        # Prepare file
        await self._prepare_file()
        
        # Join with code
        logger.info("Joining session...")
        msg = json.dumps({"type": "join", "code": self.code}).encode('utf-8')
        await self._send(msg, self.server_addr)
        
        # Wait for connection
        while self._running and not self._connected:
            await asyncio.sleep(0.1)
        
        if not self._running:
            return
        
        logger.info("✅ Connected! Waiting for receiver to be ready...")
        
        # Wait for READY signal from receiver
        timeout = 10.0
        start_wait = time.time()
        while self._running and not self.peer_ready:
            if time.time() - start_wait > timeout:
                logger.error("Timeout waiting for receiver READY signal")
                self._running = False
                return
            await asyncio.sleep(0.1)
        
        if not self._running:
            return
        
        logger.info("Receiver ready! Starting file transfer...")
        
        # Send file info
        await self._send_file_info()
        
        # Send chunks with sliding window
        await self._send_file()
    
    async def _prepare_file(self):
        """Prepare file for sending"""
        self.file_size = os.path.getsize(self.file_path)
        self.file_name = os.path.basename(self.file_path)
        self.total_chunks = (self.file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        
        logger.info(f"File size: {self.file_size / (1024*1024):.2f} MB")
        logger.info(f"Total chunks: {self.total_chunks}")
        
        # Calculate SHA256
        logger.info("Calculating SHA256...")
        sha256 = hashlib.sha256()
        with open(self.file_path, 'rb') as f:
            while True:
                data = f.read(1024 * 1024)
                if not data:
                    break
                sha256.update(data)
        self.file_sha256 = sha256.hexdigest()
        logger.info(f"SHA256: {self.file_sha256}")
        
        # Load file into memory (or chunk by chunk for large files)
        with open(self.file_path, 'rb') as f:
            for i in range(self.total_chunks):
                chunk_data = f.read(CHUNK_SIZE)
                self.chunks[i] = chunk_data
    
    async def _send_file_info(self):
        """Send file metadata with retry until ACK"""
        info = struct.pack('!BIQQ', MSG_FILE_INFO, len(self.file_name),
                          self.file_size, self.total_chunks)
        info += self.file_name.encode('utf-8')
        info += bytes.fromhex(self.file_sha256)
        
        # Send FILE_INFO repeatedly until ACK received
        max_retries = 20
        retry_interval = 0.5
        
        for retry in range(max_retries):
            if not self._running:
                return
            
            await self._send(info, self._peer_addr)
            
            if retry == 0:
                logger.info("Sent file info, waiting for ACK...")
            else:
                logger.info(f"Retrying file info ({retry + 1}/{max_retries})...")
            
            # Wait for ACK with timeout
            start_wait = time.time()
            while time.time() - start_wait < retry_interval:
                if self.file_info_acked:
                    logger.info("FILE_INFO acknowledged!")
                    return
                await asyncio.sleep(0.05)
        
        logger.error("Failed to send FILE_INFO - no ACK after retries")
        self._running = False
    
    async def _send_file(self):
        """Send file with sliding window and FINAL_ACK verification"""
        self.progress = ProgressBar(self.file_size, self.file_name)
        
        # Phase 1: Send all chunks until we think they're all ACKed
        while self._running and len(self.acked_chunks) < self.total_chunks:
            await self._send_window()
            await asyncio.sleep(0.001)
        
        if not self._running:
            return
        
        # Phase 2: Send DONE and wait for FINAL_ACK
        max_final_retries = 10
        for retry in range(max_final_retries):
            # Send DONE
            done_msg = struct.pack('!B', MSG_DONE)
            await self._send(done_msg, self._peer_addr)
            
            if retry == 0:
                logger.info("Sent DONE, waiting for FINAL_ACK...")
            
            # Wait for FINAL_ACK
            self.final_ack_received = False
            start_wait = time.time()
            while time.time() - start_wait < 2.0 and not self.final_ack_received:
                await asyncio.sleep(0.05)
            
            if not self.final_ack_received:
                logger.warning(f"FINAL_ACK timeout, retry {retry + 1}/{max_final_retries}")
                continue
            
            # Check if receiver has all chunks
            if len(self.peer_received_chunks) == self.total_chunks:
                self.progress.finish()
                logger.info("✅ Transfer complete! Receiver confirmed all chunks.")
                self._running = False
                return
            
            # Find missing chunks
            missing_chunks = set(range(self.total_chunks)) - self.peer_received_chunks
            logger.info(f"Resending {len(missing_chunks)} missing chunks...")
            
            # Resend missing chunks
            for chunk_id in sorted(missing_chunks):
                if not self._running:
                    return
                await self._send_chunk(chunk_id)
                await asyncio.sleep(0.001)
        
        logger.error("Failed to get complete FINAL_ACK after retries")
        self._running = False
    
    async def _send_window(self):
        """Send chunks in current window"""
        for chunk_id in range(self.window_start, 
                              min(self.window_start + WINDOW_SIZE, self.total_chunks)):
            if chunk_id not in self.acked_chunks:
                await self._send_chunk(chunk_id)
    
    async def _send_chunk(self, chunk_id: int):
        """Send a single chunk"""
        chunk_data = self.chunks[chunk_id]
        crc = zlib.crc32(chunk_data)
        
        # Format: type(1) + chunk_id(4) + crc(4) + data
        msg = struct.pack('!BII', MSG_CHUNK, chunk_id, crc) + chunk_data
        await self._send(msg, self._peer_addr)
        self.send_times[chunk_id] = time.time()
    
    async def _receive_loop(self):
        """Main receive loop - Windows compatible with blocking recv + executor"""
        while self._running:
            try:
                data, addr = await self._loop.run_in_executor(None, self._recv_blocking)
                if data is None:
                    continue
                
                # DEBUG: Log all received packets (only if --debug)
                logger.debug(f"📥 RECV from {addr}, len={len(data)}, peer_addr={self._peer_addr}, connected={self._connected}")
                
                if addr == self.server_addr:
                    await self._handle_server_message(data)
                elif self._connected and addr == self._peer_addr:
                    await self._handle_peer_message(data)
                # Flexible port matching: accept packet from same IP even if port differs
                # NAT may use different outgoing port than reported by server
                elif not self._connected and self._peer_addr and addr[0] == self._peer_addr[0]:
                    if addr != self._peer_addr:
                        logger.info(f"Peer port updated: {self._peer_addr[1]} -> {addr[1]}")
                        self._peer_addr = addr  # Update to actual port!
                    self._connected = True
                    logger.info(f"✅ Hole punch succeeded with {addr}")
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self._running:
                    logger.error(f"Receive error: {e}")
    
    async def _handle_server_message(self, data: bytes):
        """Handle message from server"""
        try:
            msg = json.loads(data.decode('utf-8'))
        except:
            return
        
        msg_type = msg.get("type")
        
        if msg_type == "code_assigned":
            code = msg.get("code")
            logger.info(f"📋 Your code: {code}")
            logger.info("Share this code with the sender!")
        
        elif msg_type == "peer":
            peer = msg.get("peer")
            if peer:
                self._peer_addr = (peer[0], peer[1])
                logger.info(f"Peer discovered: {self._peer_addr}")
        
        elif msg_type == "joined":
            peer = msg.get("peer")
            if peer:
                self._peer_addr = (peer[0], peer[1])
                logger.info(f"Peer discovered: {self._peer_addr}")
        
        elif msg_type == "go":
            start_at = msg.get("start_at")
            if start_at and self._peer_addr:
                asyncio.create_task(self._do_hole_punch(start_at))
        
        elif msg_type == "error":
            error = msg.get("error")
            logger.error(f"Server error: {error}")
            self._running = False
    
    async def _handle_peer_message(self, data: bytes):
        """Handle message from peer"""
        if len(data) < 1:
            return
        
        # Update activity timestamp for inactivity detection
        self.last_activity = time.time()
        
        msg_type = data[0]
        
        if msg_type == MSG_READY and self.mode == 'send':
            self.peer_ready = True
            logger.info("Received READY signal from receiver")
        
        elif msg_type == MSG_FILE_INFO and self.mode == 'receive':
            await self._handle_file_info(data)
        
        elif msg_type == MSG_CHUNK and self.mode == 'receive':
            await self._handle_chunk(data)
        
        elif msg_type == MSG_FILE_INFO_ACK and self.mode == 'send':
            self.file_info_acked = True
            logger.info("Received FILE_INFO_ACK from receiver")
        
        elif msg_type == MSG_ACK and self.mode == 'send':
            await self._handle_ack(data)
        
        elif msg_type == MSG_FINAL_ACK and self.mode == 'send':
            await self._handle_final_ack(data)
        
        elif msg_type == MSG_DONE and self.mode == 'receive':
            await self._handle_done()
    
    async def _handle_file_info(self, data: bytes):
        """Handle file info from sender"""
        # Need at least 21 bytes for header (1 type + 4 name_len + 8 size + 8 chunks)
        if len(data) < 21:
            return
        
        try:
            # Python 3.11 requires EXACT buffer size for struct.unpack
            # !IQQ = 4+8+8 = 20 bytes, so use data[1:21]
            name_len, self.file_size, self.total_chunks = struct.unpack('!IQQ', data[1:21])
            
            # Check if we have enough data for filename and SHA256
            # Header is 21 bytes (1 type + 4 name_len + 8 size + 8 chunks)
            required_len = 21 + name_len + 32
            if len(data) < required_len:
                logger.warning(f"FILE_INFO incomplete: {len(data)}/{required_len} bytes")
                return
            
            self.file_name = data[21:21+name_len].decode('utf-8')
            self.file_sha256 = data[21+name_len:21+name_len+32].hex()
            
            logger.info(f"Receiving: {self.file_name}")
            logger.info(f"Size: {self.file_size / (1024*1024):.2f} MB")
            logger.info(f"Chunks: {self.total_chunks}")
            
            self.progress = ProgressBar(self.file_size, self.file_name)
            
            # Send FILE_INFO_ACK
            ack_msg = struct.pack('!B', MSG_FILE_INFO_ACK)
            await self._send(ack_msg, self._peer_addr)
            logger.info("Sent FILE_INFO_ACK")
            
        except Exception as e:
            logger.error(f"Failed to parse file info: {e}")
    
    async def _handle_chunk(self, data: bytes):
        """Handle chunk from sender"""
        try:
            chunk_id, crc_received = struct.unpack('!II', data[1:9])
            chunk_data = data[9:]
            
            # Verify CRC
            crc_calculated = zlib.crc32(chunk_data)
            if crc_calculated != crc_received:
                logger.warning(f"CRC mismatch for chunk {chunk_id}")
                return
            
            # Store chunk
            if chunk_id not in self.received_chunks:
                self.chunks[chunk_id] = chunk_data
                self.received_chunks.add(chunk_id)
                
                # Update progress
                bytes_received = len(self.received_chunks) * CHUNK_SIZE
                if self.progress:
                    self.progress.update(min(bytes_received, self.file_size))
            
            # Send ACK periodically (reduced frequency for better performance)
            current_time = time.time()
            if current_time - self.last_ack_time > 0.1:  # Every 100ms
                await self._send_ack()
                self.last_ack_time = current_time
        
        except Exception as e:
            logger.error(f"Failed to handle chunk: {e}")
    
    async def _send_ack(self):
        """Send ACK with received chunk ranges"""
        # Build ranges of received chunks
        if not self.received_chunks:
            return
        
        sorted_chunks = sorted(self.received_chunks)
        ranges = []
        start = sorted_chunks[0]
        end = sorted_chunks[0]
        
        for chunk_id in sorted_chunks[1:]:
            if chunk_id == end + 1:
                end = chunk_id
            else:
                ranges.append((start, end))
                start = chunk_id
                end = chunk_id
        ranges.append((start, end))
        
        # Pack ACK: type(1) + num_ranges(2) + ranges
        msg = struct.pack('!BH', MSG_ACK, len(ranges))
        for start, end in ranges:
            msg += struct.pack('!II', start, end)
        
        await self._send(msg, self._peer_addr)
    
    async def _send_final_ack(self):
        """Send FINAL_ACK with count of received chunks (same format as ACK but with FINAL_ACK type)"""
        if not self.received_chunks:
            # No chunks received - send empty FINAL_ACK
            msg = struct.pack('!BH', MSG_FINAL_ACK, 0)
            await self._send(msg, self._peer_addr)
            return
        
        sorted_chunks = sorted(self.received_chunks)
        ranges = []
        start = sorted_chunks[0]
        end = sorted_chunks[0]
        
        for chunk_id in sorted_chunks[1:]:
            if chunk_id == end + 1:
                end = chunk_id
            else:
                ranges.append((start, end))
                start = chunk_id
                end = chunk_id
        ranges.append((start, end))
        
        # Pack FINAL_ACK: type(1) + num_ranges(2) + ranges
        msg = struct.pack('!BH', MSG_FINAL_ACK, len(ranges))
        for start, end in ranges:
            msg += struct.pack('!II', start, end)
        
        await self._send(msg, self._peer_addr)
        logger.info(f"Sent FINAL_ACK with {len(self.received_chunks)} chunks")
    
    async def _handle_ack(self, data: bytes):
        """Handle ACK from receiver"""
        try:
            num_ranges = struct.unpack('!H', data[1:3])[0]
            offset = 3
            
            for _ in range(num_ranges):
                start, end = struct.unpack('!II', data[offset:offset+8])
                offset += 8
                for chunk_id in range(start, end + 1):
                    self.acked_chunks.add(chunk_id)
            
            # Update window start
            while self.window_start in self.acked_chunks and self.window_start < self.total_chunks:
                self.window_start += 1
            
            # Update progress
            bytes_acked = len(self.acked_chunks) * CHUNK_SIZE
            if self.progress:
                self.progress.update(min(bytes_acked, self.file_size))
        
        except Exception as e:
            logger.error(f"Failed to handle ACK: {e}")
    
    async def _handle_final_ack(self, data: bytes):
        """Handle FINAL_ACK from receiver - contains what receiver actually has"""
        try:
            self.peer_received_chunks.clear()
            num_ranges = struct.unpack('!H', data[1:3])[0]
            offset = 3
            
            for _ in range(num_ranges):
                start, end = struct.unpack('!II', data[offset:offset+8])
                offset += 8
                for chunk_id in range(start, end + 1):
                    self.peer_received_chunks.add(chunk_id)
            
            self.final_ack_received = True
            logger.info(f"Received FINAL_ACK: Peer has {len(self.peer_received_chunks)}/{self.total_chunks} chunks")
            
            if len(self.peer_received_chunks) == self.total_chunks:
                logger.info("✅ Receiver confirmed all chunks received!")
            else:
                missing = self.total_chunks - len(self.peer_received_chunks)
                logger.warning(f"Receiver missing {missing} chunks - will resend")
        
        except Exception as e:
            logger.error(f"Failed to handle FINAL_ACK: {e}")
    
    async def _handle_done(self):
        """Handle transfer completion - send FINAL_ACK with received chunks"""
        logger.info(f"Received DONE - have {len(self.received_chunks)}/{self.total_chunks} chunks")
        
        # Send FINAL_ACK with list of received chunks
        await self._send_final_ack()
        
        # Check if complete
        if len(self.received_chunks) != self.total_chunks:
            logger.warning(f"Transfer incomplete! Missing {self.total_chunks - len(self.received_chunks)} chunks")
            logger.info("Waiting for missing chunks...")
            return
        
        # Complete - write file
        output_path = Path(self.file_name)
        logger.info(f"Writing file: {output_path}")
        
        with open(output_path, 'wb') as f:
            for i in range(self.total_chunks):
                f.write(self.chunks[i])
        
        # Verify SHA256
        logger.info("Verifying SHA256...")
        sha256 = hashlib.sha256()
        with open(output_path, 'rb') as f:
            while True:
                data = f.read(1024 * 1024)
                if not data:
                    break
                sha256.update(data)
        
        calculated_sha256 = sha256.hexdigest()
        if calculated_sha256 == self.file_sha256:
            if self.progress:
                self.progress.finish()
            logger.info("✅ Transfer complete! SHA256 verified.")
        else:
            logger.error(f"SHA256 mismatch! Expected {self.file_sha256}, got {calculated_sha256}")
            output_path.unlink()
        
        self._running = False
    
    async def _do_hole_punch(self, start_at: float):
        """Perform UDP hole punching"""
        if not self._peer_addr:
            return
        
        # Wait until start time
        now = time.time()
        if start_at > now:
            await asyncio.sleep(start_at - now)
        
        logger.info(f"Starting hole punch to {self._peer_addr}")
        
        interval = 1.0 / PUNCH_RATE
        end_time = time.time() + PUNCH_DURATION
        punch_data = b'\x00' * 8
        punch_count = 0
        
        while time.time() < end_time and self._running and not self._connected:
            await self._send(punch_data, self._peer_addr)
            punch_count += 1
            if punch_count <= 3 or punch_count % 50 == 0:
                logger.debug(f"📤 PUNCH #{punch_count} sent to {self._peer_addr}")
            await asyncio.sleep(interval)
        
        if self._connected:
            logger.info(f"Hole punch succeeded! (sent {punch_count} packets)")
            logger.info("Sending confirmation packets...")
            # IMPORTANT: Send extra packets to ensure peer receives them too!
            # We may have received their packet but they haven't received ours yet
            for _ in range(20):
                await self._send(punch_data, self._peer_addr)
                await asyncio.sleep(0.05)
            logger.info("Confirmation packets sent!")
        else:
            logger.error(f"❌ Hole punch failed after {punch_count} packets - aborting")
            self._running = False
    
    async def _inactivity_check(self):
        """Check for peer inactivity and abort transfer if timeout exceeded"""
        while self._running:
            if self._connected and time.time() - self.last_activity > self.inactivity_timeout:
                logger.error(f"⚠️ Inactivity timeout ({self.inactivity_timeout}s) - peer disconnected?")
                self._running = False
                break
            await asyncio.sleep(5)  # Check every 5 seconds


async def main():
    import argparse
    parser = argparse.ArgumentParser(description='UDP File Transfer Client')
    parser.add_argument('--server', '-s', required=True, help='Server address (host:port)')
    parser.add_argument('--mode', '-m', choices=['send', 'receive'], required=True,
                       help='Mode: send or receive')
    parser.add_argument('--file', '-f', help='File to send (sender mode)')
    parser.add_argument('--code', '-c', help='Transfer code (sender mode)')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    # Enable debug logging if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Parse server address
    parts = args.server.split(':')
    server_addr = (parts[0], int(parts[1]))
    
    # Validate arguments
    if args.mode == 'send':
        if not args.file:
            logger.error("--file required for send mode")
            return
        if not args.code:
            logger.error("--code required for send mode")
            return
    
    client = FileTransferClient(
        server_addr=server_addr,
        mode=args.mode,
        file_path=args.file,
        code=args.code
    )
    
    # Handle signals (Linux/Unix only - Windows uses KeyboardInterrupt)
    import signal
    import platform
    
    if platform.system() != 'Windows':
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: setattr(client, '_running', False))
    
    await client.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted")
