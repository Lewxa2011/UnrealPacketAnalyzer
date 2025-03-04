import socket
import sys
import time
import struct
import argparse
import binascii
import json
import threading
from datetime import datetime
import re

class UnrealUDPClient:
    def __init__(self, ip, port, timeout=5):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.socket = None
        self.connected = False
        self.running = False
        self.receive_thread = None
        self.response_patterns = {}
        self.successful_packets = []
        
    def connect(self):
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Creating UDP socket for {self.ip}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(self.timeout)
            
            if self.perform_handshake():
                self.connected = True
                
                self.running = True
                self.receive_thread = threading.Thread(target=self.receive_loop)
                self.receive_thread.daemon = True
                self.receive_thread.start()
                
                return True
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Handshake failed")
                return False
                
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Connection failed: {str(e)}")
            return False
    
    def perform_handshake(self):
        try:
            handshake = bytes.fromhex("0c00000001000000fefefefe")
            
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending handshake: {binascii.hexlify(handshake).decode()}")
            self.socket.sendto(handshake, (self.ip, self.port))
            
            try:
                data, addr = self.socket.recvfrom(1024)
                if data:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Handshake successful!")
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Response: {binascii.hexlify(data).decode()}")
                    self.analyze_response(handshake, data)
                    try:
                        text = data.decode('utf-8', errors='ignore')
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Text form: {text}")
                    except:
                        pass
                    return True
            except socket.timeout:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] No response to handshake (timeout)")
            except Exception as e:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Error during handshake: {str(e)}")
            
            return False
            
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Handshake failed: {str(e)}")
            return False
    
    def send_packet(self, data, description=None):
        if not self.connected or not self.socket:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Not connected")
            return False
        
        try:
            if description:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending {description}: {binascii.hexlify(data).decode()}")
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Sent: {binascii.hexlify(data).decode()}")
            
            self.socket.sendto(data, (self.ip, self.port))
            return True
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Failed to send: {str(e)}")
            return False
    
    def receive_loop(self):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Started receive loop")
        
        while self.running and self.socket:
            try:
                self.socket.settimeout(0.5)
                data, addr = self.socket.recvfrom(4096)
                
                if data:
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Received ({len(data)} bytes): {binascii.hexlify(data).decode()}")
                    last_sent = getattr(self, 'last_sent', None)
                    if last_sent:
                        self.analyze_response(last_sent, data)
                    
                    try:
                        text = data.decode('utf-8', errors='ignore')
                        if any(c.isprintable() for c in text):
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Text form: {text}")
                        
                        try:
                            json_data = json.loads(text)
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] JSON data: {json.dumps(json_data, indent=2)}")
                        except:
                            pass
                    except:
                        pass
            except socket.timeout:
                pass
            except Exception as e:
                if self.running:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Error in receive loop: {str(e)}")
    
    def analyze_response(self, sent_data, response_data):
        sent_hex = binascii.hexlify(sent_data).decode()
        resp_hex = binascii.hexlify(response_data).decode()
        
        self.successful_packets.append((sent_hex, resp_hex))
        
        if len(response_data) >= 8:
            header = resp_hex[:8]
            if header not in self.response_patterns:
                self.response_patterns[header] = []
            self.response_patterns[header].append((sent_hex, resp_hex))
        
        if len(self.successful_packets) > 1:
            try:
                prev_resp = binascii.unhexlify(self.successful_packets[-2][1])
                curr_resp = response_data
                
                if len(prev_resp) == len(curr_resp):
                    changing_positions = []
                    for i in range(len(prev_resp)):
                        if prev_resp[i] != curr_resp[i]:
                            changing_positions.append(i)
                    
                    if changing_positions:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Changing bytes at positions: {changing_positions}")
                        
                        if len(changing_positions) == 1 and prev_resp[changing_positions[0]] + 1 == curr_resp[changing_positions[0]]:
                            print(f"[{datetime.now().strftime('%H:%M:%S')}] Possible counter at position {changing_positions[0]}")
            except:
                pass
    
    def disconnect(self):
        self.running = False
        
        if self.receive_thread:
            self.receive_thread.join(timeout=1)
        
        if self.socket:
            try:
                self.socket.close()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Disconnected from {self.ip}:{self.port}")
            except Exception as e:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Error during disconnection: {str(e)}")
        
        self.connected = False
        self.socket = None
        
        self.print_response_summary()
    
    def print_response_summary(self):
        if not self.successful_packets:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] No successful packets recorded")
            return
            
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] === Response Pattern Analysis ===")
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Total successful packets: {len(self.successful_packets)}")
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Common response headers:")
        for header, packets in self.response_patterns.items():
            print(f"[{datetime.now().strftime('%H:%M:%S')}]   Header '{header}' seen {len(packets)} times")
        
        command_response_lengths = {}
        for sent, resp in self.successful_packets:
            command_type = sent[:8]
            if command_type not in command_response_lengths:
                command_response_lengths[command_type] = []
            command_response_lengths[command_type].append(len(resp) // 2)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Most informative command types:")
        sorted_commands = sorted(command_response_lengths.items(), 
                                key=lambda x: max(x[1]) if x[1] else 0, 
                                reverse=True)
        
        for cmd, lengths in sorted_commands[:5]:
            print(f"[{datetime.now().strftime('%H:%M:%S')}]   Command '{cmd}' max response: {max(lengths) if lengths else 0} bytes")
        
        analyze_response_patterns([resp for _, resp in self.successful_packets])

    def deep_probe_unreal_protocol(self):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting deep protocol probe based on successful patterns...")
        
        base_pattern = bytes.fromhex("0c00000001000000fefefefe")
        
        variations = [
            bytes.fromhex("fefefefe"),
            bytes.fromhex("fefefeff"),
            bytes.fromhex("fefeffff"),
            bytes.fromhex("01010101"),
            bytes.fromhex("ffffffff"),
            bytes.fromhex("deadbeef"),
            bytes.fromhex("cafebabe"),
        ]
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] === Testing data field variations ===")
        for i, variation in enumerate(variations):
            packet = base_pattern[:8] + variation
            desc = f"data field variation {i+1}/{len(variations)}"
            self.last_sent = packet
            self.send_packet(packet, desc)
            time.sleep(0.5)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] === Testing command ID sequence ===")
        for cmd_id in range(1, 21):
            packet = struct.pack("<II", 0x0c, cmd_id) + bytes.fromhex("fefefefe")
            desc = f"command ID {cmd_id}/20"
            self.last_sent = packet
            self.send_packet(packet, desc)
            time.sleep(0.3)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] === Testing counter sequence ===")
        for counter in range(1, 11):
            packet = struct.pack("<II", 0x0c, 0x01) + struct.pack("<I", counter)
            desc = f"counter value {counter}/10"
            self.last_sent = packet
            self.send_packet(packet, desc)
            time.sleep(0.3)
            
        print(f"[{datetime.now().strftime('%H:%M:%S')}] === Testing payload size ===")
        for size in [4, 8, 12, 16, 20, 24, 32]:
            payload = b"\xAA" * size
            packet = struct.pack("<II", size + 8, 0x01) + payload
            desc = f"payload size {size} bytes"
            self.last_sent = packet
            self.send_packet(packet, desc)
            time.sleep(0.3)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] === Testing specific server info requests ===")
        
        info_patterns = [
            struct.pack("<III", 0x0c, 0x01, 0x03),
            struct.pack("<II", 0x08, 0x02),
            struct.pack("<II", 0x08, 0x03),
            bytes.fromhex("070000000700000000010000"),
            bytes.fromhex("0c00000002000000fefefefe"),
            struct.pack("<I", 0x0c + len('{"cmd":"info"}')) + b'{"cmd":"info"}',
        ]
        
        for i, pattern in enumerate(info_patterns):
            desc = f"info request pattern {i+1}/{len(info_patterns)}"
            self.last_sent = pattern
            self.send_packet(pattern, desc)
            time.sleep(1.0)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Deep protocol probe completed.")
    
    def exhaustive_binary_probing(self):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting exhaustive binary protocol probe...")
        
        base_bytes = bytes.fromhex("0c00000001000000fefefefe")
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] === Testing command byte values ===")
        for cmd in range(32):
            packet = base_bytes[:4] + bytes([cmd]) + base_bytes[5:]
            desc = f"command byte {cmd}/31"
            self.last_sent = packet
            self.send_packet(packet, desc)
            time.sleep(0.2)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] === Testing known game protocol patterns ===")
        patterns = [
            bytes.fromhex("0100"),
            bytes.fromhex("0300"),
            bytes.fromhex("01000000") + struct.pack("<I", int(time.time() % 10000)),
            bytes.fromhex("05000000") + struct.pack("<I", 0x01) + bytes.fromhex("00000000"),
            bytes.fromhex("07000000DEADBEEF"),
            bytes.fromhex("0900000001000000") + struct.pack("<I", int(time.time() % 10000)),
            bytes.fromhex("0A000000") + struct.pack("<II", 0x00, 0x01),
            bytes.fromhex("FF01") + struct.pack("<I", int(time.time() % 10000)),
        ]
        
        for i, pattern in enumerate(patterns):
            desc = f"known pattern {i+1}/{len(patterns)}"
            self.last_sent = pattern
            self.send_packet(pattern, desc)
            time.sleep(0.3)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] === Testing small binary modifications ===")
        for i in range(len(base_bytes)):
            packet = base_bytes[:i] + bytes([0xFF]) + base_bytes[i+1:]
            desc = f"modified byte {i}/{len(base_bytes)-1}"
            self.last_sent = packet
            self.send_packet(packet, desc)
            time.sleep(0.2)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Exhaustive binary probing completed.")
    
    def header_fuzzing(self):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting header fuzzing...")
        
        sizes = [0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30]
        
        for size in sizes:
            packet = struct.pack("<III", size, 0x01, 0xfefefefe)
            desc = f"size field 0x{size:02x}"
            self.last_sent = packet
            self.send_packet(packet, desc)
            time.sleep(0.2)
        
        for size in [0x10, 0x14, 0x18, 0x1c, 0x20]:
            padding_size = size - 0x0c
            if padding_size > 0:
                packet = struct.pack("<II", size, 0x01) + bytes.fromhex("fefefefe") + (b"\x00" * padding_size)
                desc = f"size 0x{size:02x} with padding"
                self.last_sent = packet
                self.send_packet(packet, desc)
                time.sleep(0.2)
        
        for cmd in range(1, 6):
            for subcmd in range(1, 6):
                packet = struct.pack("<III", 0x0c, cmd, subcmd)
                desc = f"cmd 0x{cmd:02x} subcmd 0x{subcmd:02x}"
                self.last_sent = packet
                self.send_packet(packet, desc)
                time.sleep(0.2)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Header fuzzing completed.")
    
    def protocol_structure_test(self):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting protocol structure testing...")
        
        patterns = [
            bytes.fromhex("ec810102") + bytes.fromhex("00000000") + bytes.fromhex("00000000"),
            bytes.fromhex("ec810182") + bytes.fromhex("00000000") + bytes.fromhex("00000000"),
            bytes.fromhex("0c000000") + bytes.fromhex("ec810102") + bytes.fromhex("00000000"),
            bytes.fromhex("0c000000") + bytes.fromhex("ec810182") + bytes.fromhex("00000000"),
            bytes.fromhex("ec000000") + bytes.fromhex("01000000") + bytes.fromhex("fefefefe"),
            bytes.fromhex("ec000000") + bytes.fromhex("02000000") + bytes.fromhex("fefefefe"),
            bytes.fromhex("0c000000") + bytes.fromhex("01000000") + bytes.fromhex("9c8c5c0c"),
            bytes.fromhex("ec810102") + bytes.fromhex("9c8c5c0c") + bytes.fromhex("c30000"),
        ]
        
        for i, pattern in enumerate(patterns):
            desc = f"protocol mirror {i+1}/{len(patterns)}"
            self.last_sent = pattern
            self.send_packet(pattern, desc)
            time.sleep(0.5)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Protocol structure testing completed.")
        
    def try_all_known_formats(self):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting comprehensive probing of server...")

        self.try_format_category("Standard Unreal Engine Queries", [
            bytes.fromhex("FFFFFFFF5C6F6E6E656374696F6E6C657373506C61796572"),
            bytes.fromhex("FFFFFFFF496E666F"),
            bytes.fromhex("FFFFFFFF537461747573"),
            bytes.fromhex("FFFFFFFF426173696353746174"),
            bytes.fromhex("FFFFFFFF47657453657276657252756C6573"),
            bytes.fromhex("FFFFFFFF506C617965727300"),
        ])
        
        self.try_format_category("UE4/5 Specific Queries", [
            b"GET /info HTTP/1.1\r\n\r\n",
            b"GET /status HTTP/1.1\r\n\r\n",
            b"GET /players HTTP/1.1\r\n\r\n",
            bytes.fromhex("0700000007000000"),
            bytes.fromhex("0700000001000000"),
            bytes.fromhex("0700000000000000"),
        ])
        
        binary_formats = []
        for msg_type in range(0, 16):
            packet = struct.pack("<II", msg_type, 0) + bytes.fromhex("00000000")
            binary_formats.append(packet)
            
        for data_val in [1, 2, 0xFEFEFEFE, 0xFFFFFFFF]:
            packet = struct.pack("<II", 1, data_val) + bytes.fromhex("00000000")
            binary_formats.append(packet)
        
        self.try_format_category("Binary Format Variations", binary_formats)
        
        self.try_format_category("Game-Specific Formats", [
            bytes.fromhex("0000000078000000FFFFFFFF00000000"),
            bytes.fromhex("0E00000001000000FFFFFFFF00000000"),
            bytes.fromhex("FFFFFFFF54536F7572636520456E67696E6520517565727900"),
        ])
        
        json_requests = [
            '{"cmd":"info"}',
            '{"command":"status"}',
            '{"request":"server_info"}',
            '{"type":"query","command":"info"}',
            '{"type":"query","command":"status"}',
            '{"type":"query","command":"players"}',
            '{"deployment_id":"request","station_id":"request"}',
            '{"message":"getServerInfo"}',
            '{"action":"getStatus"}',
        ]
        
        json_binary = [json_str.encode('utf-8') for json_str in json_requests]
        self.try_format_category("JSON Requests", json_binary)
        
        text_commands = [
            "info",
            "status",
            "getstatus",
            "getinfo",
            "players",
            "list",
            "serverinfo",
            "stats",
            "help",
            "query",
            "rules",
            "version",
            "map",
            "rcon",
            "connect",
            "hello",
            "ping",
        ]
        
        text_binary = [cmd.encode('utf-8') for cmd in text_commands]
        self.try_format_category("Text Commands", text_binary)
        
        handshake_variations = []
        original = bytes.fromhex("0c00000001000000fefefefe")
        
        for first_byte in range(0x00, 0x10):
            packet = bytes([first_byte]) + original[1:]
            handshake_variations.append(packet)
            
        for msg_type in range(0x00, 0x10):
            packet = original[:4] + bytes([msg_type]) + original[5:]
            handshake_variations.append(packet)
            
        self.try_format_category("Handshake Variations", handshake_variations)
        
        self.deep_probe_unreal_protocol()
        self.exhaustive_binary_probing()
        self.header_fuzzing()
        self.protocol_structure_test()
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Comprehensive probing completed.")
    
    def try_format_category(self, category_name, formats):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] === Testing {category_name} ===")
        for i, fmt in enumerate(formats):
            self.last_sent = fmt
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Trying format {i+1}/{len(formats)}: {binascii.hexlify(fmt).decode()}")
            self.send_packet(fmt)
            time.sleep(0.5)
        time.sleep(1)
    
    def send_info_request(self):
        formats = [
            bytes.fromhex("0100000000000000"),
            b"info",
            b"status",
            b"getstatus",
            b'{"cmd":"info"}',
            b'{"command":"getinfo"}',
            b'{"request":"server_info"}',
            bytes.fromhex("10000000020000000000000000000000"),
            b'{"deployment_id":"request","station_id":"request"}',
        ]
        
        for i, fmt in enumerate(formats):
            self.last_sent = fmt
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Trying info request format {i+1}: {fmt}")
            self.send_packet(fmt)
            time.sleep(1)
    
    def send_custom_command(self, command):
        try:
            if all(c in '0123456789abcdefABCDEF' for c in command):
                data = bytes.fromhex(command)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending hex command: {command}")
                self.last_sent = data
                return self.send_packet(data)
            else:
                data = command.encode('utf-8')
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending text command: {command}")
                self.last_sent = data
                return self.send_packet(data)
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Failed to send custom command: {str(e)}")
            return False
    
    def test_specific_command_variations(self, base_cmd):
        try:
            data = bytes.fromhex(base_cmd)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Testing variations of command: {base_cmd}")
            
            variations = []
            
            for i in range(len(data)):
                for val in [0x00, 0x01, 0x02, 0xFF]:
                    variation = data[:i] + bytes([val]) + data[i+1:]
                    variations.append(variation)
            
            for i, var in enumerate(variations):
                desc = f"variation {i+1}/{len(variations)}"
                self.last_sent = var
                self.send_packet(var, desc)
                time.sleep(0.2)
                
            return True
        except Exception as e:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Failed to test command variations: {str(e)}")
            return False

def analyze_response_patterns(responses):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Analyzing {len(responses)} response patterns...")
    
    by_length = {}
    for resp_hex in responses:
        length = len(resp_hex) // 2
        if length not in by_length:
            by_length[length] = []
        by_length[length].append(resp_hex)
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Response length distribution:")
    for length, resps in sorted(by_length.items()):
        print(f"[{datetime.now().strftime('%H:%M:%S')}]   {length} bytes: {len(resps)} responses")
    
    headers = {}
    for resp_hex in responses:
        if len(resp_hex) >= 16:
            header = resp_hex[:16]
            if header not in headers:
                headers[header] = 0
            headers[header] += 1
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Common response headers:")
    for header, count in sorted(headers.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"[{datetime.now().strftime('%H:%M:%S')}]   '{header}': {count} occurrences")
    
    if len(responses) >= 2:
        consistent_positions = find_consistent_positions(responses)
        varying_positions = find_varying_positions(responses)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Byte position analysis:")
        print(f"[{datetime.now().strftime('%H:%M:%S')}]   Consistent positions: {consistent_positions[:10]}{'...' if len(consistent_positions) > 10 else ''}")
        print(f"[{datetime.now().strftime('%H:%M:%S')}]   Varying positions: {varying_positions[:10]}{'...' if len(varying_positions) > 10 else ''}")
        
        potential_counters = identify_counters(responses)
        if potential_counters:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Potential counter/sequence positions:")
            for pos, values in potential_counters.items():
                print(f"[{datetime.now().strftime('%H:%M:%S')}]   Position {pos}: Values {values[:5]}{'...' if len(values) > 5 else ''}")
    
    infer_message_structure(responses)

def find_consistent_positions(responses):
    byte_responses = [bytes.fromhex(r) for r in responses]
    
    min_length = min(len(r) for r in byte_responses)
    
    consistent_positions = []
    for i in range(min_length):
        values = set(r[i] for r in byte_responses)
        if len(values) == 1:
            consistent_positions.append(i)
    
    return consistent_positions

def find_varying_positions(responses):
    byte_responses = [bytes.fromhex(r) for r in responses]
    
    min_length = min(len(r) for r in byte_responses)
    
    varying_positions = []
    for i in range(min_length):
        values = set(r[i] for r in byte_responses)
        if len(values) > 1:
            varying_positions.append(i)
    
    return varying_positions

def identify_counters(responses):
    byte_responses = [bytes.fromhex(r) for r in responses]
    
    min_length = min(len(r) for r in byte_responses)
    
    potential_counters = {}
    for i in range(min_length):
        values = [r[i] for r in byte_responses]
        unique_values = set(values)
        if 1 < len(unique_values) <= min(10, len(responses) // 2):
            potential_counters[i] = list(unique_values)
    
    return potential_counters

def infer_message_structure(responses):
    if not responses:
        return
    
    byte_responses = [bytes.fromhex(r) for r in responses]
    length_counts = {}
    for resp in byte_responses:
        length = len(resp)
        if length not in length_counts:
            length_counts[length] = 0
        length_counts[length] += 1
    
    most_common_length = max(length_counts.items(), key=lambda x: x[1])[0]
    common_responses = [r for r in byte_responses if len(r) == most_common_length]
    
    if len(common_responses) < 2:
        return
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Inferring message structure from {len(common_responses)} responses of length {most_common_length} bytes:")
    
    fixed_positions = []
    varying_positions = []
    
    for i in range(most_common_length):
        values = set(r[i] for r in common_responses)
        if len(values) == 1:
            fixed_positions.append(i)
        else:
            varying_positions.append(i)
    
    structure_info = []
    current_type = None
    current_start = 0
    
    for i in range(most_common_length):
        is_fixed = i in fixed_positions
        new_type = "fixed" if is_fixed else "variable"
        
        if current_type is None:
            current_type = new_type
        elif current_type != new_type:
            structure_info.append((current_start, i - 1, current_type))
            current_start = i
            current_type = new_type
    
    if current_type is not None:
        structure_info.append((current_start, most_common_length - 1, current_type))
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Inferred message segments:")
    for start, end, segment_type in structure_info:
        length = end - start + 1
        position = f"bytes {start}-{end}"
        
        if segment_type == "fixed":
            sample_value = common_responses[0][start:end+1].hex()
            print(f"[{datetime.now().strftime('%H:%M:%S')}]   {position} ({length} bytes): Fixed value: {sample_value}")
            
            if length in [1, 2, 4, 8]:
                int_val = int.from_bytes(common_responses[0][start:end+1], byteorder='little')
                print(f"[{datetime.now().strftime('%H:%M:%S')}]     Could be {length*8}-bit integer: {int_val}")
        else:
            sample_values = [resp[start:end+1].hex() for resp in common_responses[:3]]
            print(f"[{datetime.now().strftime('%H:%M:%S')}]   {position} ({length} bytes): Variable data: {', '.join(sample_values)}...")
            
            if length in [1, 2, 4, 8]:
                int_vals = [int.from_bytes(resp[start:end+1], byteorder='little') for resp in common_responses[:5]]
                if all(int_vals[i] < int_vals[i+1] for i in range(len(int_vals)-1)):
                    print(f"[{datetime.now().strftime('%H:%M:%S')}]     Possible incrementing counter: {int_vals}")
                elif all(int_vals[i] > int_vals[i+1] for i in range(len(int_vals)-1)):
                    print(f"[{datetime.now().strftime('%H:%M:%S')}]     Possible decrementing counter: {int_vals}")
            
            try:
                text_samples = [resp[start:end+1].decode('ascii', errors='ignore') for resp in common_responses[:3]]
                if any(re.search(r'[a-zA-Z]{3,}', sample) for sample in text_samples):
                    print(f"[{datetime.now().strftime('%H:%M:%S')}]     Possible text data: {', '.join(text_samples)}...")
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description='Unreal Engine UDP Protocol Analyzer')
    parser.add_argument('--ip', '-i', type=str, required=True, help='Target IP address')
    parser.add_argument('--port', '-p', type=int, required=True, help='Target port')
    parser.add_argument('--timeout', '-t', type=int, default=5, help='Socket timeout in seconds')
    parser.add_argument('--command', '-c', type=str, help='Custom command to send (hex or text)')
    parser.add_argument('--info', action='store_true', help='Send info request')
    parser.add_argument('--probe', action='store_true', help='Perform protocol probing')
    parser.add_argument('--variations', '-v', type=str, help='Test variations of a command (hex)')
    
    args = parser.parse_args()
    
    client = UnrealUDPClient(args.ip, args.port, timeout=args.timeout)
    
    try:
        if client.connect():
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Connected to {args.ip}:{args.port}")
            
            if args.info:
                client.send_info_request()
                time.sleep(2)
            
            if args.probe:
                client.try_all_known_formats()
            
            if args.variations:
                client.test_specific_command_variations(args.variations)
            
            if args.command:
                client.send_custom_command(args.command)
                time.sleep(2)
            
            if not any([args.info, args.probe, args.variations, args.command]):
                print(f"[{datetime.now().strftime('%H:%M:%S')}] No specific action requested. Entering interactive mode.")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Enter commands to send (hex or text), or type 'exit' to quit.")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Special commands: 'info', 'probe', 'deep', 'variations:HEX'")
                
                while True:
                    try:
                        cmd = input("\nCommand> ").strip()
                        
                        if cmd.lower() == 'exit':
                            break
                        elif cmd.lower() == 'info':
                            client.send_info_request()
                        elif cmd.lower() == 'probe':
                            client.try_all_known_formats()
                        elif cmd.lower() == 'deep':
                            client.deep_probe_unreal_protocol()
                        elif cmd.lower().startswith('variations:'):
                            hex_cmd = cmd.split(':', 1)[1].strip()
                            client.test_specific_command_variations(hex_cmd)
                        else:
                            client.send_custom_command(cmd)
                    except KeyboardInterrupt:
                        print("\nCtrl+C detected, exiting...")
                        break
                    except Exception as e:
                        print(f"Error: {str(e)}")
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Failed to connect to {args.ip}:{args.port}")
            
    except KeyboardInterrupt:
        print("\nCtrl+C detected, exiting...")
    finally:
        if client:
            client.disconnect()

class UnrealPacketAnalyzer:
    """Advanced packet analyzer for Unreal Engine protocol responses"""
    
    def __init__(self):
        self.known_patterns = {
            "handshake": bytes.fromhex("0c00000001000000fefefefe"),
            "info_req": bytes.fromhex("FFFFFFFF496E666F"),
            "status_req": bytes.fromhex("FFFFFFFF537461747573"),
            "players_req": bytes.fromhex("FFFFFFFF506C61796572"),
        }
        
        self.message_types = {
            0x00: "Unknown",
            0x01: "Handshake",
            0x02: "Status",
            0x03: "Info",
            0x04: "Players",
            0x05: "Rules",
            0x06: "Challenge",
            0x07: "Connect",
            0x08: "Response",
            0x09: "Update",
            0x0A: "Heartbeat",
            0x0B: "Error"
        }
    
    def analyze_packet(self, packet):
        """Analyze a packet and return structural information"""
        results = {
            "size": len(packet),
            "type": "Unknown",
            "fields": [],
            "possible_text": None,
            "possible_integers": [],
            "structure": []
        }
        
        if len(packet) >= 8:
            try:
                size_field = int.from_bytes(packet[0:4], byteorder='little')
                msg_type = int.from_bytes(packet[4:8], byteorder='little')
                
                results["fields"].append({"name": "Size", "value": size_field, "bytes": packet[0:4].hex()})
                results["fields"].append({"name": "Type", "value": msg_type, "bytes": packet[4:8].hex()})
                
                if msg_type in self.message_types:
                    results["type"] = self.message_types[msg_type]
                
                results["structure"].append({"type": "header", "start": 0, "end": 7})
                
                if len(packet) > 8:
                    results["structure"].append({"type": "payload", "start": 8, "end": len(packet)-1})
                    
                    try:
                        text = packet[8:].decode('utf-8', errors='strict')
                        if "{" in text and "}" in text:
                            try:
                                json_data = json.loads(text)
                                results["json_data"] = json_data
                                results["type"] = "JSON Response"
                            except:
                                pass
                    except:
                        pass
            except:
                pass
        
        try:
            text = packet.decode('utf-8', errors='ignore')
            printable_text = ''.join(c for c in text if c.isprintable())
            if len(printable_text) >= 3:
                results["possible_text"] = printable_text
        except:
            pass
        
        for offset in range(0, len(packet) - 3, 4):
            if offset + 4 <= len(packet):
                int_val = int.from_bytes(packet[offset:offset+4], byteorder='little')
                if int_val < 10000000:
                    results["possible_integers"].append({"offset": offset, "value": int_val})
        
        return results

if __name__ == "__main__":
    main()