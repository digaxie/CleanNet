"""TLS ClientHello fragmentation and desync strategies."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import random
import socket
from typing import Any, Awaitable, Callable


Writer = Any


@dataclass
class StrategyRuntimeContext:
    record_fragments: Callable[[int], None]
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


def _find_extensions_length_offset(data):
    """Absolute offset of the 2-byte ClientHello extensions-length field, or None."""
    try:
        if len(data) < 43 or data[0] != 0x16:
            return None
        pos = 43
        if pos >= len(data):
            return None
        sid_len = data[pos]
        pos += 1 + sid_len
        if pos + 2 > len(data):
            return None
        cs_len = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2 + cs_len
        if pos >= len(data):
            return None
        cm_len = data[pos]
        pos += 1 + cm_len
        if pos + 2 > len(data):
            return None
        return pos
    except Exception:
        return None


def _find_sni_offset(data):
    try:
        ext_len_off = _find_extensions_length_offset(data)
        if ext_len_off is None:
            return None
        pos = ext_len_off + 2
        ext_end = min(pos + int.from_bytes(data[pos-2:pos], 'big'), len(data))
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(data[pos:pos+2], 'big')
            ext_len = int.from_bytes(data[pos+2:pos+4], 'big')
            if ext_type == 0:
                return pos
            pos += 4 + ext_len
        return None
    except Exception:
        return None

def _sni_split_point(data):
    """Calculate the split point at the middle of the SNI name (within payload)."""
    sni_off = _find_sni_offset(data)
    if not sni_off or sni_off <= 5:
        return None
    payload = data[5:]
    sni_payload_idx = sni_off - 5
    if (sni_payload_idx + 9) > len(payload):
        return None
    try:
        name_len = int.from_bytes(payload[sni_payload_idx+7:sni_payload_idx+9], 'big')
        if 0 < name_len < 500 and (sni_payload_idx + 9 + name_len) <= len(payload):
            return sni_payload_idx + 9 + (name_len // 2)
    except Exception:
        pass
    return None


def _is_tls_handshake(data):
    return len(data) > 5 and data[0] == 0x16 and data[1] == 0x03


def _sni_hostname_range(data):
    """Absolute ``(start, end)`` offsets of the SNI hostname bytes, or None."""
    sni_off = _find_sni_offset(data)
    if not sni_off or sni_off + 9 > len(data):
        return None
    name_len = int.from_bytes(data[sni_off+7:sni_off+9], 'big')
    start = sni_off + 9
    end = start + name_len
    if not 0 < name_len < 500 or end > len(data):
        return None
    return start, end


def _build_tls_records(content_type, tls_version, payload, cuts):
    """Cut ``payload`` at the given offsets and wrap each piece in its own TLS record.

    Only the record framing changes; the handshake bytes the server reassembles are
    identical to the client's, so the TLS transcript (and therefore Finished) still
    matches. Strategies must never alter the ClientHello content itself.
    """
    records = []
    prev = 0
    for cut in sorted(set(cuts)) + [len(payload)]:
        if cut <= prev or cut > len(payload):
            continue
        frag = payload[prev:cut]
        records.append(bytes([content_type]) + tls_version + len(frag).to_bytes(2, 'big') + frag)
        prev = cut
    return records


def _enable_nodelay(writer):
    sock = writer.transport.get_extra_info('socket') if getattr(writer, "transport", None) else None
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass


class StrategySet:
    def __init__(self, context: StrategyRuntimeContext):
        self.ctx = context

    async def strategy_direct(self, writer, data):
        writer.write(data)
        await writer.drain()
    
    async def strategy_host_split(self, writer, data):
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            sni_offset = _find_sni_offset(data)
            if sni_offset and sni_offset > 0:
                writer.write(data[:sni_offset])
                await writer.drain()
                await self.ctx.sleep(0.005)
                writer.write(data[sni_offset:])
                await writer.drain()
                self.ctx.record_fragments(1)
                return
        writer.write(data)
        await writer.drain()
    
    async def strategy_fragment_light(self, writer, data):
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            mid = min(len(data) // 2, 100)
            writer.write(data[:mid])
            await writer.drain()
            await self.ctx.sleep(0.02)
            writer.write(data[mid:])
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_tls_record_frag(self, writer, data):
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
    
            frag1 = payload[:split_at]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
    
            writer.write(rec1)
            await writer.drain()
            await self.ctx.sleep(0.01)
            writer.write(rec2)
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_fragment_burst(self, writer, data):
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            sock = writer.transport.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
            sni_offset = _find_sni_offset(data)
            if sni_offset and sni_offset > 5:
                writer.write(data[:5])
                writer.write(data[5:sni_offset])
                writer.write(data[sni_offset:])
            else:
                third = max(len(data) // 3, 1)
                writer.write(data[:third])
                writer.write(data[third:third*2])
                writer.write(data[third*2:])
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_desync(self, writer, data):
        sock = writer.transport.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
        await self.ctx.sleep(0.2)
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            sni_offset = _find_sni_offset(data)
            if sni_offset and sni_offset > 5:
                content_type = data[0]
                tls_version = data[1:3]
                payload = data[5:]
                split_at = sni_offset - 5
                frag1 = payload[:split_at]
                rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
                frag2 = payload[split_at:]
                rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
                writer.write(rec1)
                writer.write(rec2)
                await writer.drain()
            else:
                writer.write(data)
                await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_fragment_heavy(self, writer, data):
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            sock = writer.transport.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
            # Split TLS header bytes with small delays
            writer.write(data[:1])
            await writer.drain()
            await self.ctx.sleep(0.01)
            writer.write(data[1:5])
            await writer.drain()
            await self.ctx.sleep(0.01)
            # Send remaining in larger chunks (16 bytes) with minimal delays
            remaining = data[5:]
            for i in range(0, len(remaining), 16):
                writer.write(remaining[i:i + 16])
                await writer.drain()
                await self.ctx.sleep(0.001)
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_sni_shuffle(self, writer, data):
        try:
            if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
                content_type = data[0]
                tls_version = data[1:3]
                record_len = int.from_bytes(data[3:5], 'big')
                payload = data[5:5+record_len]
                split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
                split_at = max(1, min(split_at, len(payload) - 1))
    
                frag1 = payload[:split_at]
                frag2 = payload[split_at:]
                rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
                rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
    
                writer.write(rec1)
                await writer.drain()
                await self.ctx.sleep(0.02)
                writer.write(rec2)
                await writer.drain()
                self.ctx.record_fragments(2)
            else:
                writer.write(data)
                await writer.drain()
        except Exception:
            writer.write(data)
            await writer.drain()
    
    async def strategy_fake_tls_inject(self, writer, data):
        """Send a fake TLS ChangeCipherSpec record before the real ClientHello to confuse DPI."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            tls_version = data[1:3]
            # Fake ChangeCipherSpec record (content type 0x14) with 1-byte payload
            fake_record = b'\x14' + tls_version + b'\x00\x01\x01'
            writer.write(fake_record)
            await writer.drain()
            await self.ctx.sleep(0.005)
            writer.write(data)
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_triple_split(self, writer, data):
        """Split TLS record into 3 proper TLS records: header area, SNI area, rest."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            sni_off = _find_sni_offset(data)
            if sni_off and sni_off > 5:
                s1 = sni_off - 5
                sni_sp = _sni_split_point(data)
                s2 = sni_sp if sni_sp and sni_sp > s1 else s1 + max((len(payload) - s1) // 2, 1)
            else:
                third = max(len(payload) // 3, 1)
                s1, s2 = third, third * 2
            s1 = max(1, min(s1, len(payload) - 2))
            s2 = max(s1 + 1, min(s2, len(payload) - 1))
            for frag in (payload[:s1], payload[s1:s2], payload[s2:]):
                rec = bytes([content_type]) + tls_version + len(frag).to_bytes(2, 'big') + frag
                writer.write(rec)
                await writer.drain()
                await self.ctx.sleep(0.008)
            self.ctx.record_fragments(2)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_sni_padding(self, writer, data):
        """Inject a TLS padding extension into ClientHello to inflate packet size past DPI buffers."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            try:
                # Find extensions area and add padding extension (type 0x0015)
                sni_off = _find_sni_offset(data)
                ext_len_off = _find_extensions_length_offset(data)
                # Build padding extension: type=0x0015, length=256, data=256 zero bytes
                pad_ext = b'\x00\x15\x01\x00' + (b'\x00' * 256)
                if (
                    sni_off and sni_off > 43
                    and ext_len_off is not None
                    and len(data) - 5 + len(pad_ext) <= 16384
                ):
                    record_payload = bytearray(data[5:])
                    # Fix the extensions total length. Without this the server parses the
                    # padding as the end of the extension block and rejects the ClientHello.
                    ext_len_idx = ext_len_off - 5
                    old_ext_len = int.from_bytes(record_payload[ext_len_idx:ext_len_idx+2], 'big')
                    record_payload[ext_len_idx:ext_len_idx+2] = (old_ext_len + len(pad_ext)).to_bytes(2, 'big')
                    # Fix the handshake length (payload[1:4])
                    old_hs_len = int.from_bytes(record_payload[1:4], 'big')
                    record_payload[1:4] = (old_hs_len + len(pad_ext)).to_bytes(3, 'big')
                    # Insert padding extension right before SNI extension
                    insert_at = sni_off - 5
                    new_payload = bytes(record_payload[:insert_at]) + pad_ext + bytes(record_payload[insert_at:])
                    # Rebuild as single TLS record
                    content_type = data[0]
                    tls_version = data[1:3]
                    new_record = bytes([content_type]) + tls_version + len(new_payload).to_bytes(2, 'big') + new_payload
                    writer.write(new_record)
                    await writer.drain()
                    self.ctx.record_fragments(1)
                    return
            except Exception:
                pass
        writer.write(data)
        await writer.drain()
    
    async def strategy_reverse_frag(self, writer, data):
        """Send TLS record fragments in reverse order - second half first, then first half."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            frag1 = payload[:split_at]
            frag2 = payload[split_at:]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            # Send second fragment first
            writer.write(rec2)
            await writer.drain()
            await self.ctx.sleep(0.01)
            writer.write(rec1)
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_slow_drip(self, writer, data):
        """Send data byte-by-byte with delays to evade DPI reassembly timeouts."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            sock = writer.transport.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
            # Send first 10 bytes one by one with delays (covers TLS header + start of handshake)
            drip_len = min(10, len(data))
            for i in range(drip_len):
                writer.write(data[i:i+1])
                await writer.drain()
                await self.ctx.sleep(0.05)
            # Send rest in one chunk
            if drip_len < len(data):
                writer.write(data[drip_len:])
                await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_oob_inline(self, writer, data):
        """Use TCP urgent (OOB) data to inject a byte that DPI may process but server ignores."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            sock = writer.transport.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    # Send 1 byte as OOB/urgent data - DPI sees it inline, TLS server ignores it
                    sock.send(b'\x00', socket.MSG_OOB)
                except Exception:
                    pass
            await self.ctx.sleep(0.005)
            # Now send real data fragmented at SNI
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            frag1 = payload[:split_at]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            writer.write(rec1)
            await writer.drain()
            await self.ctx.sleep(0.01)
            writer.write(rec2)
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_dot_shuffle(self, writer, data):
        """Randomize the case of the SNI hostname - some DPI does case-sensitive matching."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            try:
                sni_off = _find_sni_offset(data)
                if sni_off:
                    # SNI extension: type(2) + len(2) + list_len(2) + type(1) + name_len(2) + name
                    name_start = sni_off + 9
                    name_len = int.from_bytes(data[sni_off+7:sni_off+9], 'big')
                    if name_start + name_len <= len(data) and 0 < name_len < 500:
                        modified = bytearray(data)
                        for i in range(name_start, name_start + name_len):
                            ch = modified[i]
                            if 0x61 <= ch <= 0x7a:  # lowercase a-z
                                if (i % 2) == 0:
                                    modified[i] = ch - 32  # to uppercase
                        # Send as TLS record fragments with modified SNI
                        content_type = modified[0]
                        tls_version = bytes(modified[1:3])
                        payload = bytes(modified[5:])
                        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
                        split_at = max(1, min(split_at, len(payload) - 1))
                        frag1 = payload[:split_at]
                        rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
                        frag2 = payload[split_at:]
                        rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
                        writer.write(rec1)
                        await writer.drain()
                        await self.ctx.sleep(0.01)
                        writer.write(rec2)
                        await writer.drain()
                        self.ctx.record_fragments(1)
                        return
            except Exception:
                pass
        writer.write(data)
        await writer.drain()
    
    async def strategy_tls_multi_record(self, writer, data):
        """Split TLS into 5-6 tiny records (1-byte payload each) to overwhelm DPI reassembly."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            # Send first 5 bytes as individual 1-byte TLS records
            send_individual = min(5, len(payload))
            for i in range(send_individual):
                rec = bytes([content_type]) + tls_version + b'\x00\x01' + payload[i:i+1]
                writer.write(rec)
                await writer.drain()
                await self.ctx.sleep(0.003)
            # Send remaining as one record
            if send_individual < len(payload):
                rest = payload[send_individual:]
                rec = bytes([content_type]) + tls_version + len(rest).to_bytes(2, 'big') + rest
                writer.write(rec)
                await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_tls_mixed_delay(self, writer, data):
        """TLS record fragmentation with random delays between fragments to break DPI timing."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            import random
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            frag1 = payload[:split_at]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            writer.write(rec1)
            await writer.drain()
            # Random delay between 5-50ms
            await self.ctx.sleep(random.uniform(0.005, 0.05))
            writer.write(rec2)
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_sni_split_byte(self, writer, data):
        """Split into 3 TLS records: pre-SNI, single SNI middle byte, post-SNI."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            sni_mid = _sni_split_point(data)
            if sni_mid and 1 < sni_mid < len(payload) - 1:
                # 3 records: everything before SNI middle, 1 byte at SNI middle, everything after
                parts = [payload[:sni_mid], payload[sni_mid:sni_mid+1], payload[sni_mid+1:]]
                for p in parts:
                    rec = bytes([content_type]) + tls_version + len(p).to_bytes(2, 'big') + p
                    writer.write(rec)
                    await writer.drain()
                    await self.ctx.sleep(0.008)
                self.ctx.record_fragments(2)
            else:
                # Fallback to regular 2-way split
                split_at = min(len(payload) // 2, 50)
                split_at = max(1, min(split_at, len(payload) - 1))
                frag1 = payload[:split_at]
                rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
                frag2 = payload[split_at:]
                rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
                writer.write(rec1)
                await writer.drain()
                await self.ctx.sleep(0.008)
                writer.write(rec2)
                await writer.drain()
                self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_header_fragment(self, writer, data):
        """Fragment the TLS record header itself across TCP segments - DPI can't even parse the header."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            sock = writer.transport.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
            # Send TLS header in 2 pieces: content_type+version (3 bytes), then length (2 bytes)
            writer.write(data[:3])
            await writer.drain()
            await self.ctx.sleep(0.01)
            writer.write(data[3:5])
            await writer.drain()
            await self.ctx.sleep(0.01)
            # Send payload in 2 chunks at SNI split point
            payload_start = 5
            sni_mid = _sni_split_point(data)
            if sni_mid:
                abs_split = payload_start + sni_mid
                writer.write(data[payload_start:abs_split])
                await writer.drain()
                await self.ctx.sleep(0.005)
                writer.write(data[abs_split:])
            else:
                writer.write(data[payload_start:])
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_tls_zero_frag(self, writer, data):
        """Inject zero-length TLS records between real fragments to confuse DPI state machine."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            # Zero-length TLS record (valid per spec, servers silently ignore)
            empty_rec = bytes([content_type]) + tls_version + b'\x00\x00'
            frag1 = payload[:split_at]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            # Pattern: empty, frag1, empty, empty, frag2
            writer.write(empty_rec)
            await writer.drain()
            await self.ctx.sleep(0.003)
            writer.write(rec1)
            await writer.drain()
            await self.ctx.sleep(0.005)
            writer.write(empty_rec)
            await writer.drain()
            writer.write(empty_rec)
            await writer.drain()
            await self.ctx.sleep(0.003)
            writer.write(rec2)
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_tls_frag_overlap(self, writer, data):
        """Send overlapping TLS record fragments - DPI can't resolve which data to use."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            # First record: payload up to split_at + 4 extra overlap bytes
            overlap = min(4, len(payload) - split_at)
            frag1 = payload[:split_at + overlap]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            # Second record: starts from split_at (overlaps by 'overlap' bytes)
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            writer.write(rec1)
            await writer.drain()
            await self.ctx.sleep(0.008)
            writer.write(rec2)
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_tls_version_mix(self, writer, data):
        """Send TLS record fragments with different version bytes to confuse DPI session tracking."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            payload = data[5:]
            # Three different TLS versions
            versions = [b'\x03\x01', b'\x03\x03', b'\x03\x02']  # TLS 1.0, 1.2, 1.1
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            # Split into 3 parts
            s1 = max(1, split_at // 2)
            s2 = split_at
            parts = [payload[:s1], payload[s1:s2], payload[s2:]]
            for i, part in enumerate(parts):
                ver = versions[i % len(versions)]
                rec = bytes([content_type]) + ver + len(part).to_bytes(2, 'big') + part
                writer.write(rec)
                await writer.drain()
                await self.ctx.sleep(0.005)
            self.ctx.record_fragments(2)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_tls_random_pad_frag(self, writer, data):
        """Split TLS payload into random-sized chunks (3-30 bytes) to defeat DPI pattern matching."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            pos = 0
            while pos < len(payload):
                # Random chunk size between 3 and 30 bytes
                chunk_size = random.randint(3, 30)
                chunk = payload[pos:pos + chunk_size]
                rec = bytes([content_type]) + tls_version + len(chunk).to_bytes(2, 'big') + chunk
                writer.write(rec)
                await writer.drain()
                await self.ctx.sleep(random.uniform(0.002, 0.008))
                pos += chunk_size
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_tls_interleaved_ccs(self, writer, data):
        """Interleave fake CCS and Alert records between ClientHello fragments to disrupt DPI state."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            # Fake ChangeCipherSpec record (type 0x14)
            fake_ccs = b'\x14' + tls_version + b'\x00\x01\x01'
            # Fake Alert record (type 0x15) - warning level, close_notify
            fake_alert = b'\x15' + tls_version + b'\x00\x02\x01\x00'
            frag1 = payload[:split_at]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            # Send: CCS -> frag1 -> Alert -> frag2 -> CCS
            writer.write(fake_ccs)
            await writer.drain()
            await self.ctx.sleep(0.003)
            writer.write(rec1)
            await writer.drain()
            await self.ctx.sleep(0.005)
            writer.write(fake_alert)
            await writer.drain()
            await self.ctx.sleep(0.003)
            writer.write(rec2)
            await writer.drain()
            await self.ctx.sleep(0.003)
            writer.write(fake_ccs)
            await writer.drain()
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()
    
    async def strategy_tcp_window_frag(self, writer, data):
        """Combine small TCP window with TLS record fragmentation to force tiny TCP segments."""
        if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
            sock = writer.transport.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256)
                except Exception:
                    pass
            content_type = data[0]
            tls_version = data[1:3]
            payload = data[5:]
            split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
            split_at = max(1, min(split_at, len(payload) - 1))
            frag1 = payload[:split_at]
            rec1 = bytes([content_type]) + tls_version + len(frag1).to_bytes(2, 'big') + frag1
            frag2 = payload[split_at:]
            rec2 = bytes([content_type]) + tls_version + len(frag2).to_bytes(2, 'big') + frag2
            # Send each record byte-by-byte in small bursts to create tiny TCP segments
            for chunk in [rec1, rec2]:
                for i in range(0, len(chunk), 5):
                    writer.write(chunk[i:i+5])
                    await writer.drain()
                    await self.ctx.sleep(0.002)
                await self.ctx.sleep(0.005)
            # Restore send buffer
            if sock:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                except Exception:
                    pass
            self.ctx.record_fragments(1)
        else:
            writer.write(data)
            await writer.drain()

    async def strategy_sni_multi_record(self, writer, data):
        """Spread the SNI hostname over many tiny TLS records (3 hostname bytes each).

        sni_split_byte cuts the name at one point; DPI that reassembles two records
        still sees the full name. Here no single record holds more than 3 bytes of it.
        """
        if not _is_tls_handshake(data):
            writer.write(data)
            await writer.drain()
            return
        payload = data[5:]
        name = _sni_hostname_range(data)
        if name:
            start, end = name[0] - 5, name[1] - 5
            cuts = [start] + list(range(start + 3, end, 3)) + [end]
        else:
            cuts = [max(1, min(len(payload) // 2, 50))]
        records = _build_tls_records(data[0], data[1:3], payload, cuts)
        for rec in records:
            writer.write(rec)
            await writer.drain()
        self.ctx.record_fragments(max(1, len(records) - 1))

    async def strategy_sni_tcp_drip(self, writer, data):
        """Send only the SNI hostname as tiny TCP segments, everything else in bulk.

        slow_drip drips the first 10 bytes (the record header); this drips the part
        DPI actually matches on, 2 bytes per segment, without touching TLS framing.
        """
        name = _sni_hostname_range(data) if _is_tls_handshake(data) else None
        if not name:
            writer.write(data)
            await writer.drain()
            return
        _enable_nodelay(writer)
        start, end = name
        writer.write(data[:start])
        await writer.drain()
        await self.ctx.sleep(0.003)
        for i in range(start, end, 2):
            writer.write(data[i:min(i + 2, end)])
            await writer.drain()
            await self.ctx.sleep(0.002)
        writer.write(data[end:])
        await writer.drain()
        self.ctx.record_fragments(1)

    async def strategy_tls_record_tcp_split(self, writer, data):
        """Split at the SNI on both layers: two TLS records, each cut across TCP segments.

        Targets DPI that reassembles either TCP segments or TLS records but not both.
        """
        if not _is_tls_handshake(data):
            writer.write(data)
            await writer.drain()
            return
        _enable_nodelay(writer)
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        rec1, rec2 = _build_tls_records(data[0], data[1:3], payload, [split_at])
        # Record 1: header and body in separate segments.
        writer.write(rec1[:5])
        await writer.drain()
        await self.ctx.sleep(0.005)
        writer.write(rec1[5:])
        await writer.drain()
        await self.ctx.sleep(0.01)
        # Record 2: cut through the middle of its body.
        mid = 5 + max(1, (len(rec2) - 5) // 2)
        writer.write(rec2[:mid])
        await writer.drain()
        await self.ctx.sleep(0.005)
        writer.write(rec2[mid:])
        await writer.drain()
        self.ctx.record_fragments(2)

    async def strategy_tls_record_long_delay(self, writer, data):
        """Two TLS records split at the SNI with a 300 ms pause in between.

        Some DPI keeps per-flow reassembly state only briefly; the existing delay
        strategies pause at most 50 ms between fragments.
        """
        if not _is_tls_handshake(data):
            writer.write(data)
            await writer.drain()
            return
        payload = data[5:]
        split_at = _sni_split_point(data) or min(len(payload) // 2, 50)
        split_at = max(1, min(split_at, len(payload) - 1))
        rec1, rec2 = _build_tls_records(data[0], data[1:3], payload, [split_at])
        writer.write(rec1)
        await writer.drain()
        await self.ctx.sleep(0.3)
        writer.write(rec2)
        await writer.drain()
        self.ctx.record_fragments(1)

    def functions(self) -> dict[str, Callable[[Writer, bytes], Awaitable[None]]]:
        return {
            "direct": self.strategy_direct,
            "host_split": self.strategy_host_split,
            "fragment_light": self.strategy_fragment_light,
            "tls_record_frag": self.strategy_tls_record_frag,
            "fragment_burst": self.strategy_fragment_burst,
            "desync": self.strategy_desync,
            "fragment_heavy": self.strategy_fragment_heavy,
            "sni_shuffle": self.strategy_sni_shuffle,
            "fake_tls_inject": self.strategy_fake_tls_inject,
            "triple_split": self.strategy_triple_split,
            "sni_padding": self.strategy_sni_padding,
            "reverse_frag": self.strategy_reverse_frag,
            "slow_drip": self.strategy_slow_drip,
            "oob_inline": self.strategy_oob_inline,
            "dot_shuffle": self.strategy_dot_shuffle,
            "tls_multi_record": self.strategy_tls_multi_record,
            "tls_mixed_delay": self.strategy_tls_mixed_delay,
            "sni_split_byte": self.strategy_sni_split_byte,
            "header_fragment": self.strategy_header_fragment,
            "tls_zero_frag": self.strategy_tls_zero_frag,
            "tls_frag_overlap": self.strategy_tls_frag_overlap,
            "tls_version_mix": self.strategy_tls_version_mix,
            "tls_random_pad_frag": self.strategy_tls_random_pad_frag,
            "tls_interleaved_ccs": self.strategy_tls_interleaved_ccs,
            "tcp_window_frag": self.strategy_tcp_window_frag,
            "sni_multi_record": self.strategy_sni_multi_record,
            "sni_tcp_drip": self.strategy_sni_tcp_drip,
            "tls_record_tcp_split": self.strategy_tls_record_tcp_split,
            "tls_record_long_delay": self.strategy_tls_record_long_delay,
        }


def build_strategy_funcs(context: StrategyRuntimeContext) -> dict[str, Callable[[Writer, bytes], Awaitable[None]]]:
    return StrategySet(context).functions()

