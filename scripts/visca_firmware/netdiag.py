#!/usr/bin/env python3
"""
VISCA over IP pre-flight diagnostic tool.
Run this BEFORE the main query script to identify connection issues.
"""

import socket
import struct
import sys
import time


def diagnose_camera(host: str, port: int = 52381):
    """Run full connection diagnostics on a single camera."""

    print(f"\n{'=' * 55}")
    print(f"  DIAGNOSING: {host}:{port}")
    print(f"{'=' * 55}")

    # ---- Step 1: ICMP reachability (ping via TCP connect to common ports) ----
    print(f"\n  [1] Network reachability ...")
    reachable = False
    for test_port in [80, 443, port]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((host, test_port))
            if result == 0:
                print(f"      Port {test_port}: OPEN")
                reachable = True
            elif result == 111 or result == 10061:
                # Connection refused = host is reachable but port closed
                print(f"      Port {test_port}: REFUSED (host reachable, "
                      f"service not listening)")
                reachable = True
            else:
                print(f"      Port {test_port}: errno {result}")
        except socket.timeout:
            print(f"      Port {test_port}: TIMEOUT (unreachable or filtered)")
        except socket.error as e:
            print(f"      Port {test_port}: ERROR - {e}")
        finally:
            sock.close()

    if not reachable:
        print("\n  DIAGNOSIS: Host appears completely unreachable.")
        print("  ACTION:    Check network cabling, IP address, VLAN, "
              "and firewall rules.")
        return

    # ---- Step 2: TCP connect to VISCA port ----
    print(f"\n  [2] TCP connection to VISCA port {port} ...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    tcp_ok = False
    try:
        sock.connect((host, port))
        print(f"      TCP connection: SUCCESS")
        tcp_ok = True
    except ConnectionRefusedError:
        print(f"      TCP connection: REFUSED")
        print(f"\n  DIAGNOSIS: Camera is reachable but VISCA over IP "
              f"port {port} is closed.")
        print(f"  LIKELY CAUSES (in order):")
        print(f"    1. VISCA over IP is DISABLED in camera settings")
        print(f"    2. Another client already holds the connection")
        print(f"    3. Camera is still booting")
        print(f"    4. Wrong port number")
        print(f"\n  ACTIONS:")
        print(f"    → Open camera web UI (http://{host}) and enable "
              f"VISCA over IP")
        print(f"    → Check if another controller is connected")
        print(f"    → Wait 60-90s if camera was recently powered on")
    except socket.timeout:
        print(f"      TCP connection: TIMEOUT")
        print(f"\n  DIAGNOSIS: Port may be filtered by a firewall.")
    except socket.error as e:
        print(f"      TCP connection: ERROR - {e}")
    finally:
        if not tcp_ok:
            sock.close()
            return

    # ---- Step 3: Send VISCA inquiry ----
    print(f"\n  [3] Sending VISCA CAM_VersionInq ...")
    visca_inq = bytes([0x81, 0x09, 0x00, 0x02, 0xFF])
    header = struct.pack('>HHI', 0x0110, len(visca_inq), 1)
    packet = header + visca_inq

    try:
        sock.sendall(packet)
        data = sock.recv(1024)
        if data:
            print(f"      Response received: {data.hex()}")
            print(f"      VISCA over IP is WORKING")
        else:
            print(f"      Empty response — unexpected")
    except socket.timeout:
        print(f"      No response within timeout")
        print(f"      Camera accepted TCP but didn't respond to VISCA")
        print(f"      Possible cause: port is open but not a VISCA service")
    except socket.error as e:
        print(f"      Error: {e}")
    finally:
        sock.close()

    # ---- Step 4: UDP probe ----
    print(f"\n  [4] Probing UDP VISCA (in case TCP is wrong transport) ...")
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    usock.settimeout(3)
    try:
        usock.sendto(packet, (host, port))
        data, addr = usock.recvfrom(1024)
        print(f"      UDP response from {addr}: {data.hex()}")
        print(f"      Camera uses VISCA over UDP, not TCP!")
        print(f"      ACTION: Modify script to use UDP transport")
    except socket.timeout:
        print(f"      No UDP response (expected if TCP works)")
    except socket.error as e:
        print(f"      UDP error: {e}")
    finally:
        usock.close()

    print(f"\n  Diagnostics complete for {host}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python visca_diagnose.py <ip_address> [port]")
        print("       python visca_diagnose.py 192.168.1.100")
        print("       python visca_diagnose.py 192.168.1.100 52381")
        sys.exit(1)

    target_host = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 52381
    diagnose_camera(target_host, target_port)
