#!/usr/bin/env python3
"""
UDP File Transfer - Rendezvous Server

Coordinates peer connections with 6-digit codes.
"""

import asyncio
import socket
import json
import time
import logging
import random
import string
from typing import Dict, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

Address = Tuple[str, int]


def generate_code() -> str:
    """Generate 6-character alphanumeric code"""
    chars = string.ascii_uppercase + string.digits
    # Exclude confusing characters: 0, O, I, 1
    chars = chars.replace('0', '').replace('O', '').replace('I', '').replace('1', '')
    return ''.join(random.choices(chars, k=6))


class Session:
    """Represents a transfer session"""
    def __init__(self, code: str):
        self.code = code
        self.receiver: Optional[Address] = None
        self.sender: Optional[Address] = None
        self.created_at = time.time()
        self.last_activity = time.time()
    
    def is_complete(self) -> bool:
        return self.receiver is not None and self.sender is not None
    
    def is_expired(self, timeout: float = 300) -> bool:
        return (time.time() - self.last_activity) > timeout


class RendezvousServer:
    """Rendezvous server for UDP hole punching with code-based matching"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 9999):
        self.host = host
        self.port = port
        self.sessions: Dict[str, Session] = {}
        self.addr_to_code: Dict[Address, str] = {}  # Track which address is in which session
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    async def start(self):
        """Start the server"""
        self._loop = asyncio.get_event_loop()
        self._running = True
        
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setblocking(False)
        self._sock.bind((self.host, self.port))
        
        logger.info(f"Rendezvous server listening on {self.host}:{self.port}")
        logger.info("Press Ctrl+C to stop")
        
        # Start tasks
        recv_task = asyncio.create_task(self._receive_loop())
        cleanup_task = asyncio.create_task(self._cleanup_loop())
        stats_task = asyncio.create_task(self._stats_loop())
        
        try:
            while self._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            recv_task.cancel()
            cleanup_task.cancel()
            stats_task.cancel()
            try:
                await recv_task
                await cleanup_task
                await stats_task
            except asyncio.CancelledError:
                pass
            self._sock.close()
            logger.info("Server stopped")
    
    async def _receive_loop(self):
        """Main receive loop"""
        while self._running:
            try:
                data, addr = await self._loop.sock_recvfrom(self._sock, 65535)
                await self._handle_message(data, addr)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Receive error: {e}")
    
    async def _handle_message(self, data: bytes, addr: Address):
        """Handle incoming message"""
        try:
            msg = json.loads(data.decode('utf-8'))
        except:
            logger.warning(f"Invalid message from {addr}")
            return
        
        msg_type = msg.get("type")
        
        if msg_type == "request_code":
            # Receiver requests a new code
            await self._handle_request_code(addr)
        
        elif msg_type == "join":
            # Sender joins with a code
            code = msg.get("code")
            if code:
                await self._handle_join(addr, code)
        
        elif msg_type == "keepalive":
            # Keep session alive
            code = self.addr_to_code.get(addr)
            if code and code in self.sessions:
                self.sessions[code].last_activity = time.time()
    
    async def _handle_request_code(self, addr: Address):
        """Generate and assign a code to receiver"""
        # Generate unique code
        code = generate_code()
        while code in self.sessions:
            code = generate_code()
        
        # Create session
        session = Session(code)
        session.receiver = addr
        self.sessions[code] = session
        self.addr_to_code[addr] = code
        
        logger.info(f"Generated code {code} for receiver {addr}")
        
        # Send code to receiver
        response = json.dumps({
            "type": "code_assigned",
            "code": code,
            "public": [addr[0], addr[1]]
        }).encode('utf-8')
        await self._loop.sock_sendto(self._sock, response, addr)
    
    async def _handle_join(self, addr: Address, code: str):
        """Handle sender joining with code"""
        session = self.sessions.get(code)
        
        if not session:
            # Code doesn't exist
            response = json.dumps({
                "type": "error",
                "error": f"Invalid code: {code}"
            }).encode('utf-8')
            await self._loop.sock_sendto(self._sock, response, addr)
            logger.warning(f"Sender {addr} used invalid code: {code}")
            return
        
        if session.sender:
            # Code already in use by another sender
            response = json.dumps({
                "type": "error",
                "error": "Code already in use"
            }).encode('utf-8')
            await self._loop.sock_sendto(self._sock, response, addr)
            logger.warning(f"Sender {addr} tried to use occupied code: {code}")
            return
        
        # Assign sender
        session.sender = addr
        session.last_activity = time.time()
        self.addr_to_code[addr] = code
        
        logger.info(f"Sender {addr} joined code {code}")
        
        # Send public endpoint to sender
        sender_response = json.dumps({
            "type": "joined",
            "public": [addr[0], addr[1]],
            "peer": [session.receiver[0], session.receiver[1]]
        }).encode('utf-8')
        await self._loop.sock_sendto(self._sock, sender_response, addr)
        
        # Notify receiver about sender
        receiver_response = json.dumps({
            "type": "peer",
            "peer": [addr[0], addr[1]]
        }).encode('utf-8')
        await self._loop.sock_sendto(self._sock, receiver_response, session.receiver)
        
        # Send GO signal to both
        start_at = time.time() + 2.0
        go_msg = json.dumps({
            "type": "go",
            "start_at": start_at
        }).encode('utf-8')
        await self._loop.sock_sendto(self._sock, go_msg, session.receiver)
        await self._loop.sock_sendto(self._sock, go_msg, addr)
        
        logger.info(f"Session {code} ready - starting hole punch")
    
    async def _cleanup_loop(self):
        """Clean up expired sessions"""
        while self._running:
            try:
                await asyncio.sleep(30)
                now = time.time()
                expired = [code for code, session in self.sessions.items() 
                          if session.is_expired()]
                
                for code in expired:
                    session = self.sessions[code]
                    if session.receiver:
                        self.addr_to_code.pop(session.receiver, None)
                    if session.sender:
                        self.addr_to_code.pop(session.sender, None)
                    del self.sessions[code]
                    logger.info(f"Cleaned up expired session: {code}")
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    async def _stats_loop(self):
        """Log statistics periodically"""
        while self._running:
            try:
                await asyncio.sleep(60)
                active = len(self.sessions)
                complete = sum(1 for s in self.sessions.values() if s.is_complete())
                logger.info(f"Stats: {active} sessions ({complete} paired)")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Stats error: {e}")


async def main():
    import argparse
    parser = argparse.ArgumentParser(description='UDP File Transfer - Rendezvous Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', '-p', type=int, default=9999, help='Port to bind to')
    args = parser.parse_args()
    
    server = RendezvousServer(host=args.host, port=args.port)
    
    # Handle signals
    import signal
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: setattr(server, '_running', False))
    
    await server.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
