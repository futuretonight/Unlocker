import sys
import time
import struct
import random
import os
import subprocess
# CRC32 not used in core logic presented
# functools not used in core logic presented
# ---------- Dependency Management (Termux) -----------
def check_and_install_dependencies():
    """Checks for and guides installation of required packages in Termux."""
    print("--- Checking Dependencies (Termux Focus) ---")
    dependencies_ok = True

    # Check libusb using pkg
    # Need libusb for the backend, termux-api for termux-usb
    pkgs_to_check = ['libusb', 'termux-api']
    print(f"[*] Checking pkg packages: {', '.join(pkgs_to_check)}")
    try:
        result = subprocess.run(['pkg', 'list-installed'] + pkgs_to_check, capture_output=True, text=True, check=False)
        missing_pkgs = []
        for pkg_name in pkgs_to_check:
             if pkg_name not in result.stdout:
                 missing_pkgs.append(pkg_name)

        if missing_pkgs:
            print(f"[!] WARNING: Missing packages: {', '.join(missing_pkgs)}")
            install_cmd = ['pkg', 'install', '-y'] + missing_pkgs
            print(f"      Attempting to install using: {' '.join(install_cmd)}")
            install_result = subprocess.run(install_cmd, check=False)
            if install_result.returncode != 0:
                print(f"[!] ERROR: Failed to install {', '.join(missing_pkgs)}. Please install them manually.")
                dependencies_ok = False
            else:
                print(f"[+] {', '.join(missing_pkgs)} installation command executed (check output above).")
        else:
            print("[+] Required pkg packages seem installed.")

    except FileNotFoundError:
        print("[!] ERROR: 'pkg' command not found. Is this running in Termux?")
        dependencies_ok = False
    except Exception as e:
        print(f"[!] ERROR: Failed to check/install pkg packages: {e}")
        dependencies_ok = False

    # Check pyusb using pip
    try:
        import usb.core
        print("[+] 'pyusb' package seems installed.")
    except ImportError:
        print("[!] WARNING: 'pyusb' package not found.")
        print("      Attempting to install using: pip install pyusb")
        # Try installing pyusb
        pip_cmd = [sys.executable, "-m", "pip", "install", "pyusb"]
        try:
            install_result = subprocess.run(pip_cmd, check=True, capture_output=True, text=True)
            print("[+] 'pyusb' installation command executed successfully.")
            # Print stderr as well, some install messages go there
            if install_result.stdout: print("--- pip install stdout ---\n", install_result.stdout)
            if install_result.stderr: print("--- pip install stderr ---\n", install_result.stderr)

        except subprocess.CalledProcessError as e:
            print(f"[!] ERROR: Failed to install 'pyusb' using pip.")
            print(e.stderr)
            dependencies_ok = False
        except FileNotFoundError:
            print("[!] ERROR: 'pip' or Python executable not found. Ensure Python & pip are installed correctly.")
            dependencies_ok = False
        except Exception as e:
             print(f"[!] ERROR: Unexpected error during pip install: {e}")
             dependencies_ok = False
    except Exception as e: # Catch any other errors during import attempt itself
        print(f"[!] ERROR: An unexpected error occurred during pyusb import check: {e}")
        dependencies_ok = False
        
    if not dependencies_ok:
        print("\n[!] Critical dependencies are missing or failed to install.")
        print("      Please ensure 'libusb' and 'termux-api' (pkg install) and 'pyusb' (pip install) are working.")
        # We won't sys.exit immediately here, allow pyusb import attempt next.

    print("--- Dependency check complete ---")
    print("      IMPORTANT: Before running this script, list devices using:")
    print("      $ termux-usb -l")
    print("      and grant the necessary USB permissions on your Android device when prompted.")
    
# This needs to be run early BEFORE trying to import usb
if __name__ == "__main__":
   check_and_install_dependencies()
   # Note: check_and_install_dependencies does not strictly exit on failure,
   # to allow the next import attempt to happen and catch issues gracefully.
# ---------- Backend Loading (Termux Specific) -----------
# Define the specific path where Termux pkg installs libusb-1.0.so
TERMIX_LIBUSB_PATH = "/data/data/com.termux/files/usr/lib/libusb-1.0.so"

# Custom find_library function for pyusb to look in the Termux path
def find_termux_libusb(name):
    """Tells pyusb where to find libusb in the Termux file system."""
    # usb.backend.libusb1.get_backend expects a function that takes
    # a library name (e.g., 'libusb-1.0') and returns its full path or None.
    # Since we specifically target Termux and libusb-1.0, we can just check our fixed path.
    if os.path.exists(TERMIX_LIBUSB_PATH):
        print(f"[*] Found libusb library at {TERMIX_LIBUSB_PATH}")
        return TERMIX_LIBUSB_PATH
    else:
        print(f"[!] libusb library NOT found at expected Termux path: {TERMIX_LIBUSB_PATH}")
        print("    Ensure 'pkg install libusb' ran successfully.")
        return None # pyusb expects None if not found

# Try loading the pyusb backend using our custom find_library function
pyusb_backend = None
try:
    import usb.core
    import usb.util
    import usb.backend.libusb1 # Need to explicitly import the backend module
    print("[*] Attempting to load libusb backend...")
    pyusb_backend = usb.backend.libusb1.get_backend(find_library=find_termux_libusb)
    if pyusb_backend:
         print("[+] libusb backend loaded successfully.")
    else:
         # This happens if find_termux_libusb returned None
         print("[!] Failed to load libusb backend using Termux path.")
         print("    pyusb will now attempt to find the backend automatically, which may fail.")

except ImportError:
     # pyusb itself was not installed, check_and_install_dependencies already warned/attempted
     print("[!] Failed to import 'pyusb'. Ensure it's installed (pip install pyusb).")
     # We don't sys.exit immediately, the error will be caught when MTPNuclearCore tries to use usb.core.find
except usb.core.LibraryNotFoundError:
     # This can happen even with get_backend if the find_library fails or
     # if pyusb attempts automatic discovery later.
     print(f"[!] pyusb still reports LibraryNotFoundError after custom search.")
     print("    Please verify 'libusb-1.0.so' exists at", TERMIX_LIBUSB_PATH)
     print("    and that pkg install libusb was fully successful.")
except Exception as e:
     print(f"[!] An unexpected error occurred while trying to load pyusb backend: {type(e).__name__} - {e}")
     # Allow script to continue, might get caught later by NoBackendError


# ---------- CUSTOM MTP PROTOCOL ENGINE -----------
class MTPNuclearCore:
    MTP_CONTAINER_STRUCT = struct.Struct("<I H H I") # Ensure Little Endian per MTP spec
    # Reduced set, only using GetDeviceInfo realistically
    MTP_OPERATIONS = {
        'GetDeviceInfo': 0x1001,
        'OpenSession': 0x1002,      # Needed before most other ops
        'CloseSession': 0x1003,
        'GetStorageIDs': 0x1004, # Might be useful for listing files (complex)
        'DeviceReset': 0x1011,
        # Placeholders for brute force idea (conceptually flawed)
        # MTP does not have a 'SendPIN' or similar command
        # The 'SendObject' (0x100C, not 100B) operation code is for transferring files, not pins.
        'SendObject': 0x100C, # Corrected opcode for SendObject
    }
    # Placeholder operation codes used in non-functional exploit methods
    # THESE ARE FAKE MTP CODES AND WILL FAIL
    MTP_FAKE_EXPLOIT_OPS = {
         'Samsung_FakeExploit': 0xDEAD,
         'HTC_FakeExploit': 0xFACE,
         'Oppo_FakeExploit': 0xBEEF,
         # Removed 'Reset' as it's an actual MTP command (0x1011) used elsewhere
    }
    # MTP Response Codes
    MTP_RESPONSE_CODES = {
        0x2001: "OK",
        0x2002: "General Error",
        0x2003: "Parameter Not Supported",
        0x2004: "Operation Not Supported",
        0x2005: "Access Denied",
        0x2006: "Invalid ObjectHandle",
        0x2007: "Invalid StorageID",
        0x2008: "Invalid ObjectFormatCode",
        0x2009: "Still Capturing",
        0x200A: "Transaction Cancelled",
        0x200B: "Incomplete Transfer",
        0x200C: "Invalid Session ID",
        0x200D: "Invalid Transaction ID",
        0x200E: "No Response", # Internal pyusb timeout or read error
        0x200F: "Session Not Open", # Session must be opened first
        # Add more codes as needed for debugging
    }


    def __init__(self, backend=None):
        self.dev = None
        self.ep_out = None
        self.ep_in = None
        self.session_id = 0
        self.claimed_interface = -1
        self.backend = backend # Store the backend object

        # USB initialization happens in _bind_to_darkness now, allowing backend use
        # Call this method only once in the engine init
        # self._bind_to_darkness() # Now called from VoidwalkerEngine.__init__ after core is created

    def _find_mtp_interface(self):
        """Finds the MTP interface (often Class 6 or FF Vendor Specific)."""
        if self.dev is None: return None, -1 # Return interface descriptor and number

        try:
            # Iterate through configurations
            for cfg in self.dev:
                # Iterate through interfaces in the configuration
                for intf in cfg:
                    print(f"[*] Checking Interface {intf.bInterfaceNumber} (Class {intf.bInterfaceClass}, SubClass {intf.bInterfaceSubClass}, Protocol {intf.bInterfaceProtocol})...")
                    # Check for Still Image Class (Standard MTP/PTP)
                    if intf.bInterfaceClass == 6 and intf.bInterfaceSubClass == 1:
                         print(f"[+] Found Standard MTP/PTP Interface (Class 6, SubClass 1): Interface {intf.bInterfaceNumber}")
                         # MTP often has Protocol 0, PTP Protocol 1, both often use the same driver
                         return intf, intf.bInterfaceNumber
                    # Check for MTP Vendor Specific Class (Common Alternative for Android)
                    if intf.bInterfaceClass == 0xFF:
                        # SubClass and Protocol vary (often 0x00, 0x00) but 0xFF is the key MTP indicator here
                        print(f"[+] Found Vendor Specific MTP Interface (Class FF): Interface {intf.bInterfaceNumber}")
                        # Heuristic: Check if it has the expected bulk endpoints
                        out_ep = usb.util.find_descriptor(
                           intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_BULK
                        )
                        in_ep = usb.util.find_descriptor(
                           intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_BULK
                        )
                        # MTP requires Interrupt endpoint for events too (SubClass 1, Protocol 1 on interface 0 often),
                        # but we primarily use Bulk. Just check for Bulk here as a heuristic for FF.
                        if out_ep and in_ep:
                            print("    (Class FF interface looks like it has MTP-style bulk endpoints)")
                            return intf, intf.bInterfaceNumber
                        else:
                            print("    (Class FF interface does not seem to have the expected bulk endpoints, skipping)")


            print("[!] No standard MTP/PTP or promising Class FF interface class found.")
            return None, -1

        except usb.core.USBError as e:
            print(f"[!] USBError while searching for MTP interface: {e}")
            return None, -1
        except Exception as e:
             print(f"[!] Unexpected error during MTP interface search: {type(e).__name__} - {e}")
             return None, -1


    def _bind_to_darkness(self):
        """Attempt to find and claim a suitable MTP device interface."""
        print("[*] Searching for suitable USB device (MTP/PTP) using pyusb...")
        # Explicitly use the detected backend
        # Note: In Termux, the device needs to be exposed via `termux-usb -l` BEFORE running the script
        # And you need to grant permissions. `usb.core.find` should then see it.

        try:
            # Find the device using the explicitly loaded backend
            # This call is what might raise usb.core.NoBackendError if pyusb_backend was None and automatic detection failed
            self.dev = usb.core.find(idVendor=None, idProduct=None, find_all=False, backend=self.backend) # find_all=False gets the first one

        except usb.core.NoBackendError as e:
             # Catching NoBackendError explicitly here for a final informative message
             print("-" * 60)
             print("[!!!] FATAL USB ERROR: No Backend Available [!!!]")
             print("      'pyusb' could not find a library (like libusb) to talk to the USB ports.")
             print("      This usually means 'libusb-1.0.so' was not found at the expected path.")
             print(f"      Expected Termux path: {TERMIX_LIBUSB_PATH}")
             print("      Ensure 'pkg install libusb' completed successfully.")
             print("      Also try running 'termux-usb -l' and granting permission *before* script execution.")
             print(f"      Original Error: {e}")
             print("-" * 60)
             raise # Re-raise after printing diagnostics, as we cannot proceed

        except Exception as e:
            print(f"[!] An unexpected error occurred during usb.core.find: {type(e).__name__} - {e}")
            raise # Re-raise any other unexpected error


        if self.dev is None:
             # If find() returns None, no devices were found matching criteria OR available
             raise SystemExit("[!] No suitable USB device detected or accessible via pyusb/backend.")

        print(f"[*] Found potential device {hex(self.dev.idVendor):}: {hex(self.dev.idProduct):}")

        intf_descriptor, intf_number = self._find_mtp_interface()

        if not intf_descriptor:
            # No suitable interface on this device
            print(f"[!] Found device {hex(self.dev.idVendor)}:{hex(self.dev.idProduct)}, but no MTP/PTP interface found.")
            self.dev = None # Reset device
            raise SystemExit("[!] Failed to find a suitable MTP/PTP interface on the detected device.")

        # Proceed with claiming the found interface
        print(f"[*] Attempting to claim Interface {intf_number}")
        try:
            # Detach kernel driver if necessary (often needed on Linux/Termux)
            if self.dev.is_kernel_driver_active(intf_number):
                print(f"[*] Detaching kernel driver for Interface {intf_number}...")
                try:
                    self.dev.detach_kernel_driver(intf_number)
                    print(f"[*] Kernel driver detached for Interface {intf_number}.")
                except Exception as detach_error:
                    print(f"[!] Warning: Could not detach kernel driver: {detach_error}")
                    print("    (This may cause Access Denied errors later)")


            usb.util.claim_interface(self.dev, intf_number)
            self.claimed_interface = intf_number
            print(f"[+] Interface {self.claimed_interface} claimed successfully.")

            # Find endpoints on the *claimed* interface descriptor
            self.ep_out = usb.util.find_descriptor(
                intf_descriptor, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_BULK
            )
            self.ep_in = usb.util.find_descriptor(
                intf_descriptor, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_BULK
            )
            # MTP can also use an INTERRUPT endpoint for events, but we're not using it.
            # Just warn if it's not found, but bulk is critical.
            ep_int = usb.util.find_descriptor(
                intf_descriptor, custom_match=lambda e: usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_INTERRUPT
            )
            if not ep_int:
                 print("[!] Warning: MTP Interrupt endpoint not found on claimed interface.")


            if self.ep_out and self.ep_in:
                print(f"[+] Bulk Endpoints found: OUT=0x{self.ep_out.bEndpointAddress:02x}, IN=0x{self.ep_in.bEndpointAddress:02x}")
                print(f"[+] Bound to {hex(self.dev.idVendor)}:{hex(self.dev.idProduct)}")

            else:
                # Failed to find required endpoints on the claimed interface
                print("[!] Could not find required BULK IN/OUT endpoints on the claimed interface.")
                usb.util.release_interface(self.dev, self.claimed_interface)
                self.claimed_interface = -1
                self.dev = None # Reset dev as we cannot communicate MTP
                raise SystemExit("[!] Failed to find necessary MTP bulk endpoints on the interface.")


        except usb.core.USBError as e:
            # This is the Access Denied error often seen if permissions aren't set (termux-usb)
            print(f"[!] Failed to claim interface {intf_number} or find endpoints: {e}")
            print("    Common reasons for claim failure: Permissions issue ('termux-usb -l' required), device busy, or disconnected.")
            self.dev = None # Reset device
            raise SystemExit(f"[!] Fatal USB operation error: {e}")
        except NotImplementedError:
             # Should not happen with libusb1 backend, but good practice to catch
             print("[!] Claim Interface operation not supported by the USB backend.")
             self.dev = None
             raise SystemExit("[!] Fatal: USB backend does not support claiming interfaces.")
        except Exception as e:
             print(f"[!] Unexpected error during interface claiming or endpoint finding: {type(e).__name__} - {e}")
             self.dev = None
             raise SystemExit(f"[!] Unexpected USB setup error: {e}")


    def _forge_mtp_packet(self, container_type, code, transaction_id, params=(), payload=b''):
        """Build MTP container packets (Type 1:Command, 2:Data, 3:Response, 4:Event)."""
        # MTP Spec:
        # Container Type: UINT16 (1:Command, 2:Data, 3:Response, 4:Event)
        # Code (OperationCode for Type 1, ResponseCode for Type 3) UINT16
        # TransactionID: UINT32
        # Parameter N (UINT32) - number depends on command
        # Payload (Data): Byte array - only for Type 2 containers

        if container_type == 1: # Command
            op_code = code
            response_code = 0 # N/A for command
            expected_params_count = 5 # Minimum command includes OperationCode + TID + params
            # Add length of header (12 bytes) + parameters * 4
            packet_len = 12 + len(params) * 4

        elif container_type == 2: # Data
            op_code = 0 # N/A for data
            response_code = 0 # N/A for data
            # Data containers often omit parameters after the header, the payload *is* the data
            packet_len = 12 + len(payload)

        elif container_type == 3: # Response
            op_code = 0 # N/A for response
            response_code = code
            # Add length of header (12 bytes) + parameters * 4 (params carry return values)
            packet_len = 12 + len(params) * 4
        else:
             print(f"[!] Warning: Using unhandled MTP container type: {container_type}")
             packet_len = 12 + len(params) * 4 + len(payload) # Guess total length

        # Header structure: < Little Endian | I:UInt32 Length, H:UInt16 Type, H:UInt16 Code, I:UInt32 TransactionID
        header = struct.pack("<I H H I", packet_len, container_type, code, transaction_id)
        # MTP params are typically UInt32 Little Endian
        param_block = b''.join(struct.pack("<I", p) for p in params)

        return header + param_block + payload

    def _dissect_mtp_response(self, data):
        """Parse MTP response packets."""
        # MTP response containers should be Type 3
        # Header: Length(I), Type(H=3), ResponseCode(H), TransactionID(I)
        # Followed by Parameters (0 or more UINT32)

        if not data or len(data) < 12:
            print(f"[!] Warning: Received short/empty MTP response ({len(data)} bytes).")
            return {'code': 0x2002, 'type': 0, 'transaction_id': 0, 'params': [], 'payload': b'', 'error': 'Short/Empty response'}

        try:
             # Use correct little-endian unpacking
             length, container_type, code, transaction_id = struct.unpack("<I H H I", data[:12])
        except struct.error:
             print("[!] Warning: Failed to unpack MTP response header.")
             return {'code': 0x2002, 'type': 0, 'transaction_id': 0, 'params': [], 'payload': b'', 'error': 'Header unpack failed'}

        actual_len = len(data)
        if actual_len < length:
            print(f"[!] Warning: Incomplete MTP packet read. Declared Length: {length}, Actual Got: {actual_len}")
            # We'll process the data received, but note it's incomplete.

        # For a Type 3 (Response) container, 'code' is the ResponseCode
        response_code = code

        # Parameters are UINT32 and immediately follow the 12-byte header
        params = []
        params_data_len = length - 12 # The data after the header based on the packet's declared length
        actual_params_read = 0

        if container_type == 3: # It should be a Response
             # Read as many parameters as *actually received data allows* up to the declared length
             bytes_available_for_params = actual_len - 12
             num_params_possible = bytes_available_for_params // 4

             try:
                 for i in range(num_params_possible):
                      param_offset = 12 + (i*4)
                      params.append(struct.unpack("<I", data[param_offset:param_offset+4])[0])
                      actual_params_read += 4

             except struct.error:
                 print(f"[!] Warning: Error unpacking MTP parameters at offset {param_offset}.")
                 # Stop parsing parameters at the point of error

        elif container_type == 2: # It's a Data container
            # Data containers might contain variable data, the data *is* the payload.
            # They usually don't have parameters following the header (sometimes 0 or 1 for data length, but complex)
            # Simple approach: assume no standard parameters here after header for parsing response type
            pass
        elif container_type == 1: # It's a Command container (received unexpectedly as a response?)
             print(f"[!] Warning: Received unexpected MTP container type {container_type} (Command?) instead of Response (Type 3).")
             # Attempt to parse like a command
             bytes_available_for_params = actual_len - 12
             num_params_possible = bytes_available_for_params // 4
             try:
                for i in range(num_params_possible):
                      param_offset = 12 + (i*4)
                      params.append(struct.unpack("<I", data[param_offset:param_offset+4])[0])
                      actual_params_read += 4
             except struct.error:
                 print(f"[!] Warning: Error unpacking parameters from unexpected container type {container_type}.")


        else:
            print(f"[!] Warning: Received unhandled MTP container type: {container_type}")
            # Attempt to parse what's there
            bytes_available_for_params = actual_len - 12
            num_params_possible = bytes_available_for_params // 4
            try:
               for i in range(num_params_possible):
                     param_offset = 12 + (i*4)
                     params.append(struct.unpack("<I", data[param_offset:param_offset+4])[0])
                     actual_params_read += 4
            except struct.error:
                print(f"[!] Warning: Error unpacking parameters from unhandled container type {container_type}.")


        # Payload is whatever data remains after header and parsed parameters, up to actual_len
        payload_start_offset = 12 + actual_params_read
        payload = data[payload_start_offset:actual_len] # Use actual_len, not declared 'length'


        return {
            'length': length,
            'type': container_type,
            'code': response_code, # For Type 3, this is the ResponseCode
            'transaction_id': transaction_id,
            'params': params,
            'payload': payload
        }

    def send_command(self, operation, params=(), data_payload=b''):
        """Send an MTP Command packet (Type 1) and optionally queue a Data packet (Type 2)."""
        transaction_id = random.randint(1, 0xFFFFFFFE) # TID cannot be 0 or 0xFFFFFFFF in standard MTP

        # Send Command packet first (Type 1)
        command_packet = self._forge_mtp_packet(container_type=1, code=operation, transaction_id=transaction_id, params=params)
        print(f"[*] Sending MTP Command (OpCode=0x{operation:04X}, TID=0x{transaction_id:08X}, Params={params})")

        try:
             bytes_sent = self.ep_out.write(command_packet)
             print(f"    Sent {bytes_sent} bytes Command packet.")
        except usb.core.USBError as e:
             print(f"[!] USBError sending command 0x{operation:04X}: {e}")
             return None # Return None to indicate failure


        # If there is data to send, the device expects a Data packet (Type 2) NEXT
        # This requires knowledge of the MTP command flow - only some commands require data
        # GetDeviceInfo does NOT require sending data. SendObject *does*.
        if data_payload:
            print(f"[*] Sending MTP Data packet (TID=0x{transaction_id:08X}, Payload Length={len(data_payload)})")
            # Code field is 0 for data containers
            data_packet = self._forge_mtp_packet(container_type=2, code=0, transaction_id=transaction_id, payload=data_payload)
            try:
                 bytes_sent = self.ep_out.write(data_packet)
                 print(f"    Sent {bytes_sent} bytes Data packet.")
            except usb.core.USBError as e:
                 print(f"[!] USBError sending data for OpCode 0x{operation:04X}: {e}")
                 return None # Return None on data send failure too

        # Regardless of data presence, device typically responds with a Response packet (Type 3) LAST
        return transaction_id # Return TID to match expected response

    def receive_response(self, timeout=5000):
        """Receive an MTP Response packet (Type 3) or Data packet (Type 2)."""
        # MTP transactions typically follow:
        # 1. Command (OUT)
        # 2. [Data (OUT) - if required by command]
        # 3. [Data (IN) - if required by command]
        # 4. Response (IN) <-- We typically wait for Type 3 first, but sometimes Type 2 comes before

        # Need to read enough data. GetDeviceInfo payload can be hundreds or thousands of bytes.
        # wMaxPacketSize is typically 512 bytes or 1024 bytes for HighSpeed/SuperSpeed Bulk EPs.
        # Reading several multiples should cover common info payloads.
        max_read_size = self.ep_in.wMaxPacketSize * 64 # Attempt to read up to 64 packets
        if max_read_size < 4096: max_read_size = 4096 # Ensure minimum reasonable read size

        print(f"[*] Waiting for MTP data (up to {max_read_size} bytes) or Response (Type 3) on IN endpoint (Timeout={timeout}ms)...")

        received_data = b''
        try:
            # Read multiple chunks if needed, a full response might exceed one transfer size
            # Pyusb read often handles multiple packets internally up to the specified length
            received_data = self.ep_in.read(max_read_size, timeout)

            if not received_data:
                print("[!] Received empty data on IN endpoint.")
                return {'code': 0x200E, 'type': 0, 'transaction_id': 0, 'params': [], 'payload': b'', 'error': 'Empty read'}

            print(f"    Received {len(received_data)} bytes raw data.")
            # Note: Sometimes device sends DATA container (Type 2) before RESPONSE (Type 3)
            # A robust MTP client needs to handle sequence. For simple recon (GetDeviceInfo)
            # We expect an IN Data container *then* a Response.
            # Dissecting helps us see what arrived.

            return self._dissect_mtp_response(received_data)

        except usb.core.USBError as e:
            if e.errno == 110 or 'timeout' in str(e).lower(): # errno 110 is ETIMEDOUT on Linux/Termux
                print(f"[!] USB Timeout ({timeout}ms) waiting for MTP data.")
                return {'code': 0x200E, 'type': 0, 'transaction_id': 0, 'params': [], 'payload': b'', 'error': 'Timeout'}
            elif e.errno == 19 or 'device not responding' in str(e).lower(): # errno 19 ENODEV
                 print(f"[!] USB Error: Device not responding (Disconnected?): {e}")
                 # Could also mean session is invalid/closed by device after a failed op
                 return {'code': 0x2002, 'type': 0, 'transaction_id': 0, 'params': [], 'payload': b'', 'error': 'Device Not Responding'}
            else:
                print(f"[!] USBError receiving MTP data: {e}")
                return {'code': 0x2002, 'type': 0, 'transaction_id': 0, 'params': [], 'payload': b'', 'error': f'Receive USBError: {e}'}
        except Exception as e:
             print(f"[!] Unexpected error during MTP receive: {type(e).__name__} - {e}")
             return {'code': 0x2002, 'type': 0, 'transaction_id': 0, 'params': [], 'payload': b'', 'error': f'Unexpected receive error: {e}'}


    def execute_transaction(self, operation, params=(), data_payload=b'', timeout=5000):
         """Execute a command potentially involving OUT data, then receive IN data and/or Response."""
         # Basic transaction flow: Command (OUT) -> [Data (OUT)] -> [Data (IN)] -> Response (IN)

         expected_tid = self.send_command(operation, params, data_payload)
         if expected_tid is None:
             return {'code': 0x2002, 'error': 'Command Send Failed'} # Indicate command send failed

         # MTP transaction doesn't typically expect an immediate response right after the command.
         # It might send Data IN first, then a Response IN, or just Response IN.
         # Let's wait for ANY data first.
         time.sleep(0.1) # Short delay before first read attempt

         responses = []
         while True:
             response_data = self.receive_response(timeout=timeout)
             if response_data is None or 'error' in response_data and 'Timeout' in response_data['error']:
                  print(f"[*] No more MTP data within timeout or receive error.")
                  # If we got at least one response before timeout, that's the best we have
                  break
             # Check if the response matches our expected Transaction ID (MTP requires this)
             # Also check for special cases, e.g., a device error might send a different TID
             if response_data.get('transaction_id') != expected_tid and response_data.get('transaction_id') != 0:
                 # Warning: Received response with unexpected Transaction ID, but maybe still relevant?
                 # Append but print warning
                 print(f"[!] Warning: Received MTP data with mismatched TID (Expected: 0x{expected_tid:08X}, Got: 0x{response_data.get('transaction_id',0):08X})")

             responses.append(response_data)

             # MTP flow usually ends with a Type 3 (Response) container.
             # Stop if we receive a Type 3.
             if response_data.get('type') == 3:
                 print("[+] Received MTP Response (Type 3). Transaction completed.")
                 break # End of transaction

             # If it was a Type 2 (Data), expect another packet (either more Data or the final Response)
             # continue reading.
             if response_data.get('type') == 2:
                 print("[*] Received MTP Data (Type 2). Expecting more packets...")
                 # Adjust timeout for subsequent reads?
                 timeout = max(timeout // 2, 500) # Halve timeout but keep minimum

             # If unhandled type or very short packet, assume something is wrong and potentially break
             if response_data.get('type') not in [2, 3] or response_data.get('length',0) < 12:
                  print(f"[!] Warning: Received unexpected/short MTP packet type {response_data.get('type')}. Ending read sequence.")
                  break


         if not responses:
             print(f"[-] MTP Transaction failed: No valid response received for operation 0x{operation:04X} (TID=0x{expected_tid:08X}).")
             # Return a general error structure
             return {'code': 0x2002, 'type': 0, 'transaction_id': expected_tid, 'params': [], 'payload': b'', 'error': 'No response received'}
         else:
              # Return the *last* response, as the final Type 3 contains the operation result code
              # Store all responses for debugging if needed (e.g., data + final response)
              full_transaction_response = {
                   'final_response': responses[-1], # The last one received, expected to be Type 3
                   'all_responses': responses,       # List of all packets received for this TID
              }
              return full_transaction_response


    def get_response_code_name(self, code):
         """Maps an MTP response code to a human-readable name."""
         return self.MTP_RESPONSE_CODES.get(code, f"Unknown Code (0x{code:04X})")


    def open_session(self):
         """Opens an MTP session."""
         if self.session_id > 0:
              print(f"[*] Session {self.session_id} already appears open.")
              return True # Assume success if session ID is non-zero

         print("[*] Attempting to open MTP Session (ID=1)...")
         self.session_id = 1 # MTP session ID usually starts at 1 (must not be 0)
         # OpenSession command (0x1002) takes the desired SessionID (UInt32) as a parameter
         # The device RESPONDS with the final session ID it assigned, typically the same
         response = self.execute_transaction(self.MTP_OPERATIONS['OpenSession'], params=(self.session_id,))

         if response and 'final_response' in response:
              final_resp_code = response['final_response'].get('code')
              final_resp_tid = response['final_response'].get('transaction_id')
              # Check for OK (0x2001) response code AND correct transaction ID
              if final_resp_code == 0x2001 and final_resp_tid == response.get('final_response').get('transaction_id'): # check TID match (redundant check with execute_transaction)
                   # Optionally verify response params contain the session ID (some devices send it back)
                   print(f"[+] MTP Session {self.session_id} Opened Successfully. Response Code: {self.get_response_code_name(final_resp_code)} (0x{final_resp_code:04X}).")
                   return True
              else:
                   print(f"[!] Failed to open MTP Session {self.session_id}. Final Response Code: {self.get_response_code_name(final_resp_code)} (0x{final_resp_code:04X}). TID: 0x{final_resp_tid:08X}")
                   self.session_id = 0 # Reset session ID on failure
                   return False
         else:
              print(f"[!] Failed to execute OpenSession transaction. No valid response received.")
              self.session_id = 0
              return False

    def close_session(self):
        """Closes the current MTP session."""
        if self.session_id <= 0:
             print("[*] No active MTP session to close.")
             return # Nothing to do

        print(f"[*] Closing MTP Session {self.session_id}")
        # CloseSession command (0x1003) usually takes the SessionID as a parameter (some docs say not)
        # Based on implementations, sending it as param seems common/safe.
        response = self.execute_transaction(self.MTP_OPERATIONS['CloseSession'], params=(self.session_id,))

        # Assume success unless we get a clear error response like Invalid Session ID (0x200C)
        if response and 'final_response' in response:
             final_resp_code = response['final_response'].get('code')
             print(f"[+] Close Session command sent. Device responded with Code: {self.get_response_code_name(final_resp_code)} (0x{final_resp_code:04X})")
             if final_resp_code == 0x200C:
                  print("[!] Warning: Device indicated Invalid Session ID when attempting to close.")
             # Regardless of the code, try resetting the session ID locally
             self.session_id = 0
             return final_resp_code == 0x2001 # Return True only if OK

        else:
             print("[!] Warning: No response received for Close Session command.")
             # Assume it might have worked locally even if no response came back
             self.session_id = 0
             return False # Treat no response as not confirmed success

    def __del__(self):
        """Clean up USB resources."""
        print("\n[*] MTPCore Cleanup Initiated...")
        try:
            if self.session_id > 0:
                self.close_session() # Attempt to close session if still open

            if self.dev and self.claimed_interface != -1:
                print(f"[*] Releasing USB Interface {self.claimed_interface} for device {hex(self.dev.idVendor)}:{hex(self.dev.idProduct)}")
                try:
                    usb.util.release_interface(self.dev, self.claimed_interface)
                    self.claimed_interface = -1
                    print(f"[*] Interface {self.claimed_interface} released.")

                except usb.core.USBError as e:
                     # Device might already be disconnected/reset
                     print(f"[!] Warning: Failed to release interface: {e}")

                # Attempt to reattach kernel driver - Termux doesn't always succeed,
                # and permission model makes it less critical if termux-usb handles access.
                # Still, try for completeness on some systems.
                try:
                    # Only try if dev object is still valid and detach worked implicitly/explicitly
                    if self.dev and self.claimed_interface == -1: # Ensure it was marked as released
                         print(f"[*] Attempting to reattach kernel driver to Interface {self.claimed_interface if self.claimed_interface != -1 else 'last used'}...")
                         # The dev object *might* need to be reopened here depending on backend state
                         # For Termux/pyusb flow, just calling attach directly might work or fail silently.
                         # If the interface number is known but claim failed, attach needs the intf number.
                         # If dev is disconnected, this will likely fail.
                         # Let's try attaching to the device object, hoping it remembers the interface.
                         # This is often unreliable across different OS/backends.
                         # Removed the attempt to pass self.claimed_interface if it's -1 after release.
                         # Trying attached kernel driver without interface num often attempts for *all* interfaces.
                         print("[*] Skipping specific interface reattach - behavior varies by platform.")
                         # Alternative (less reliable in my experience for Termux):
                         # if self.claimed_interface != -1: # Only if we know the intf number
                         #    self.dev.attach_kernel_driver(self.claimed_interface)

                except Exception as attach_error:
                    # print(f"[!] Warning: Could not reattach kernel driver: {attach_error}") # Too verbose
                    pass # Silently ignore reattach failures


            # This is important for some backends like libusb1 to free up resources
            print("[*] Disposing USB device resources.")
            if self.dev:
                 usb.util.dispose_resources(self.dev)
            self.dev = None
            print("[*] Cleanup complete.")

        except Exception as e:
             print(f"[!] Error during MTPCore cleanup: {type(e).__name__} - {e}")


# ---------- ANDROID VULNERABILITY DATABASE -----------
class VulnerabilityOracle:
    # Represent versions as comparable floats or tuples if needed
    # Use floats (X.Y) for simplicity as per original code, acknowledges potential inaccuracies with X.Y.Z+
    KNOWN_CVES = {
        'Samsung': {
            # Example: Covers 5.0 up to (but not including) 6.1
            'CVE-2015-7889': {'min_os': 5.0, 'max_os': 6.1},
            # Example: Covers 8.0 up to (but not including) 11.0
            'CVE-2020-0257': {'min_os': 8.0, 'max_os': 11.0}
        },
        'HTC': {
            'CVE-2012-4220': {'min_os': 4.0, 'max_os': 4.5}, # 4.4 included (usually 4.4 is 4.4)
            'CVE-2016-0819': {'min_os': 6.0, 'max_os': 7.2} # 7.1 included (usually 7.1 is 7.1)
        },
        'Oppo': {
            'CVE-2020-12753': {'min_os': 9.0, 'max_os': 11.1}, # Up to 11.0.x
            'CVE-2021-27214': {'min_os': 10.0, 'max_os': 12.1} # Up to 12.0.x
        },
         'Google': {
             'CVE-2019-2097': {'min_os': 9.0, 'max_os': 10.1} # Example, actual MTP vulns for pixel/aosp vary
         }
         # Add other vendors/CVEs following the pattern
    }

    def __init__(self, vendor, os_version_float):
        self.vendor = vendor if vendor != "Unknown VendorID" else "Unknown" # Normalize
        self.os_version = os_version_float if os_version_float else 0.0

    def get_exploit_path(self):
        """Select optimal exploit based on device fingerprint."""
        print(f"[*] Searching for CVEs applicable to {self.vendor} Android ~{self.os_version:.1f}")
        if self.vendor == "Unknown":
            print("[!] Cannot search CVEs: Vendor Unknown.")
            return None

        vendor_cves = self.KNOWN_CVES.get(self.vendor, {})
        if not vendor_cves:
            print(f"[-] No CVEs listed for vendor '{self.vendor}'.")
            return None

        applicable_cves = []
        for cve, data in vendor_cves.items():
            # Check if the detected OS version falls within the range
            # Use >= min_os and < max_os for standard version range checks (X.Y)
            # Floating point comparison caveats apply for X.Y.Z versions truncated to X.Y
            if data['min_os'] <= self.os_version < data['max_os']:
                applicable_cves.append(cve)

        if applicable_cves:
             print(f"[+] Found potential CVE matches ({len(applicable_cves)}): {', '.join(applicable_cves)}")
             # In a real scenario, you'd pick the 'best' (e.g., latest, most reliable)
             # For this placeholder, just list them and pick the first one
             return applicable_cves[0] # Return the first found CVE
        else:
            print(f"[-] No applicable CVE found in the known list for '{self.vendor}' Android ~{self.os_version:.1f}.")
            return None

# ---------- SILENT CRACK ENGINE (CONCEPTUAL PLACEHOLDER) -----------
class ShadowBruteforcer:
    def __init__(self, mtp_core):
        self.core = mtp_core

    def execute_silent_brute(self, pin_length=4):
        """Placeholder for brute-force concept. DOES NOT WORK VIA MTP PIN GUESSING."""
        print("-" * 60)
        print("[!!!] WARNING: MTP PIN Brute-Force Placeholder - INEFFECTIVE [!!!]")
        print("      Android lock screens are NOT bypassed via guessing MTP transaction parameters.")
        print("      Hardware-backed keystores and anti-brute-force measures prevent this method.")
        print("      This section WILL NOT unlock your device by guessing the PIN over MTP.")
        print("-" * 60)
        print(f"[*] Simulating brute-force attempt for {pin_length}-digit PIN (Non-Functional)...")
        # Simulate effort and failure
        attempt_count = 0
        import itertools
        # Max 4-digit PIN is 10000 combinations
        max_sim_attempts = 1000 # Limit simulation runs
        for attempt_parts in itertools.product('0123456789', repeat=pin_length):
            if attempt_count >= max_sim_attempts:
                 print("    Simulation stopped after exceeding simulation attempt limit.")
                 break
            attempt = "".join(attempt_parts)
            attempt_count += 1
            print(f"    Attempt {attempt_count:4d}: Simulating guess {attempt}...")
            # No actual MTP command related to PIN validation exists here.
            # The original idea might have been sending dummy data packets, which won't work.
            time.sleep(random.uniform(0.01, 0.05)) # Simulate network/device delay

        print(f"[-] Simulation complete after {attempt_count} attempts.")
        print("    As expected, MTP brute-force cannot bypass screen lock.")
        # Always return None because this method cannot succeed in practice
        return None


# ---------- DEVICE FINGERPRINTING -----------
class AndroidRecon:
    # Common vendor IDs - expand this list if needed
    USB_DEVICE_MAP = {
        0x04e8: 'Samsung', # Samsung
        0x0bb4: 'HTC',      # HTC
        0x22d9: 'Oppo',     # Oppo
        0x18d1: 'Google',   # Google/Pixel
        0x0502: 'Alcatel', # Alcatel/TCL (Also uses 0x1bbb)
        0x1bbb: 'Alcatel/TCL', # Part of TCL/Alcatel group
        0x0fce: 'Sony',     # Sony Ericsson/Sony Mobile
        0x1004: 'LG',       # LG Electronics
        0x0489: 'Foxconn?',# Often Foxconn, generic or test devices
        0x05c6: 'Qualcomm?',# Often Qualcomm default or generic devices / Motorola / LG etc.
        0x2717: 'Xiaomi',  # Xiaomi
        0x19d2: 'ZTE',      # ZTE
        0x12d1: 'Huawei',   # Huawei
        0x04dd: 'Sharp',    # Sharp
        0x0409: 'NEC',      # NEC
        0x2a70: 'OnePlus',  # OnePlus (Part of Oppo group)
        0x0955: 'Nvidia', # Nvidia (Shield, etc.)
        0x8087: 'Intel', # Intel (Nexus devices, generic Android x86)
        0x0745: 'Dell', # Dell
        0x091e: 'Gigaset', # Gigaset
        # Add more as needed from https://usb-ids.arkko.net/
    }

    def __init__(self, mtp_core):
        self.core = mtp_core
        self.device_info_str = None # Store raw string repr
        self.vendor = "Unknown"
        self.model = "Unknown"
        self.serial = "Unknown"
        self.os_version_float = 0.0
        self.device_friendly_name = "Unknown Android Device"


    def _parse_mtp_string(self, data, offset):
        """Helper to parse MTP string descriptor format (length + UTF-16LE data)."""
        # MTP String format: UINT8 length, followed by (length * 2) bytes of UTF-16LE
        # The length includes the null terminator if present in the source string,
        # but the data often includes an explicit null terminator byte sequence (b'\x00\x00')
        # Let's refine the parsing slightly based on typical MTP string structures.
        # Example: length = 6 (3 chars + null), Data = 6 bytes (utf16 for 3 chars) + 2 bytes null terminator.

        if offset >= len(data):
            return None, offset # Cannot read length byte

        try:
             # Read the reported length byte (UINT8)
             str_len_bytes = data[offset] # This length is in UTF-16 *units* (16-bit characters), usually including the null
             offset += 1
             if str_len_bytes == 0:
                  return "", offset # Empty string

             # Read the string data itself (str_len_bytes * 2 bytes for UTF-16LE)
             # But, real device strings sometimes omit the length prefix or have different encodings!
             # And sometimes length *doesn't* include the null terminator.
             # The GetDeviceInfo string fields are MANDATORY Null-Terminated UNICODE Strings.
             # Let's try to find the *first* null-terminator (b'\x00\x00') after the length byte offset
             # up to a reasonable limit, assuming UTF-16 Little Endian.

             search_start = offset
             null_term_pos = data.find(b'\x00\x00', search_start)

             if null_term_pos == -1:
                 # If no null terminator found nearby, read a fixed amount and hope it's enough.
                 # Or maybe the "length byte" IS just a byte count for non-string data... MTP is tricky.
                 print(f"[!] Warning: MTP String parser: No UTF-16 null terminator (0x0000) found after offset {search_start}. Attempting heuristic read.")
                 read_len = min(256, len(data) - search_start) # Don't read excessively
                 raw_str_bytes = data[search_start : search_start + read_len]
                 next_offset = search_start + read_len
             else:
                 # Found the null terminator
                 raw_str_bytes = data[search_start : null_term_pos]
                 next_offset = null_term_pos + 2 # Skip the b'\x00\x00'

             # Decode as UTF-16 Little Endian
             decoded_string = raw_str_bytes.decode('utf-16-le', errors='ignore').strip()
             # MTP strings shouldn't have extra nulls mid-string if structure is followed, but clean up just in case.
             decoded_string = decoded_string.replace('\x00', '').strip()

             return decoded_string, next_offset

        except Exception as e:
             print(f"[!] Error parsing MTP string at offset {offset}: {type(e).__name__} - {e}")
             return None, offset # Indicate parse failure

    def _parse_device_info(self, devinfo_payload):
        """Parses the MTP GetDeviceInfo payload data (binary structure)."""
        # See PTP v1.0 spec, Section 5.1.1 (DeviceInfo dataset)
        # MTP is based on PTP, dataset structure is very similar
        # The structure includes many fixed-size fields (UINT16, UINT32) followed by arrays and strings.
        # Order of fields matters!
        # Start with fixed size fields, then parse strings/arrays based on offsets.

        if not devinfo_payload or len(devinfo_payload) < 20: # Header (12) + min fields requires > 12
            print("[!] Warning: DeviceInfo payload too short to parse basic header.")
            return

        try:
            # Unpack fixed-size initial fields (example subset, MTP structure has more)
            # Offsets based on PTP/MTP spec (little endian)
            # Total 12 fixed-size bytes *before* first string (VendorExtensionDescription)
            # Standard Version (U16) 0-1
            # MTP Vendor Extension ID (U32) 2-5
            # MTP Version (U16) 6-7
            # MTP Extensions (String - variable) 8 onwards initially - WRONG, Strings follow after fixed size things
            # The data structure is packed *binary fields*, THEN string fields *at specific offsets*.
            # PTP spec (section 5.1.1) indicates strings are at the END after arrays of UINT16/UINT32.

            # Let's read the first few known fields:
            # Standard Version (UINT16)
            # Vendor Extension ID (UINT32)
            # MTP Version (UINT16)
            # Remaining: arrays (OperationSupported, EventSupported, Properties, CaptureFormats, ImageFormats), then Strings
            # We can read the initial values reliably:

            if len(devinfo_payload) < 8: raise ValueError("Payload too short for initial MTP info.")
            std_version, vendor_ext_id, mtp_version = struct.unpack("<H I H", devinfo_payload[0:8])
            print(f"[*] MTP Header Info: Std v{std_version/100:.2f}, ExtID 0x{vendor_ext_id:08X}, MTP v{mtp_version/100:.2f}")

            # Finding the start of the strings is the challenge without parsing the full PTP dataset structure (arrays of U16/U32)
            # The PTP spec lists strings *after* all the arrays:
            # - Manufacturer (String)
            # - Model (String)
            # - Device Version (String)
            # - Serial Number (String)

            # Heuristic approach: Locate potential null-terminated strings near the end of the buffer.
            # Android MTP typically follows this structure somewhat loosely.
            # We'll try to parse 4 strings from a guessed approximate starting point.
            # Let's skip some initial bytes known not to be strings (header + array counts/first array)
            # A rough estimate: header (12 bytes), array counts (~5 * 4 bytes U32), array data... could be 50+ bytes in.
            # A safer guess: scan backwards from the end for sequences that look like UTF-16 strings + nulls.
            # Or, simply assume the order at the end: Manufacturer, Model, DeviceVersion, SerialNumber

            potential_string_start = 0
            current_offset = potential_string_start
            strings_found = []
            print("[*] Attempting heuristic parse of strings from DeviceInfo payload...")

            # Try parsing strings sequentially after initial skip (guessing structure offset)
            # A robust implementation would read array counts to find exact string start offset.
            # Example offsets from observed devices suggest strings start *at least* 60 bytes in.
            current_offset = 60 # Arbitrary heuristic starting point past binary data

            # Loop attempting to read strings using our _parse_mtp_string helper
            # We expect 4 strings: Manufacturer, Model, Device Version, Serial Number
            string_names = ['Manufacturer', 'Model', 'Device Version', 'Serial Number']
            parsed_data = {}
            for name in string_names:
                string_val, next_offset = self._parse_mtp_string(devinfo_payload, current_offset)
                if string_val is not None:
                    # print(f"    - Parsed '{name}' string: '{string_val}' (Next offset: {next_offset})")
                    parsed_data[name] = string_val
                    current_offset = next_offset
                else:
                    print(f"    [!] Failed to parse '{name}' string from offset {current_offset}.")
                    parsed_data[name] = f"Parse Error @{current_offset}"
                    # Attempt to skip forward slightly if parse failed on a likely string boundary
                    current_offset += 4 # Skip 4 bytes (size of a UINT32 or potential junk)
                    if current_offset >= len(devinfo_payload): break # Avoid infinite loop


            self.vendor = parsed_data.get('Manufacturer', 'Unknown')
            self.model = parsed_data.get('Model', 'Unknown')
            device_version_str = parsed_data.get('Device Version', 'Unknown')
            self.serial = parsed_data.get('Serial Number', 'Unknown')

            self.device_friendly_name = f"{self.vendor} {self.model} ({device_version_str})"


            # Attempt to extract OS version (Android version) from Device Version string
            # Example "Device Version" strings: "6.0.1", "Android 11", "10", "QP1A.190711.020"
            import re
            # Regex to find version numbers like X, X.Y, or X.Y.Z (specifically capturing first two parts)
            # Prefer numerical sequence over "Android" text if both present
            version_match = re.search(r'\b(\d+\.\d+\.?\d*)\b', device_version_str)
            if not version_match:
                 # Try finding just X or X.Y if X.Y.Z format isn't matched
                 version_match = re.search(r'\b(\d+\.\d+)\b', device_version_str)
            if not version_match:
                 # Finally, try just a single digit at word boundary (for "Android 12", etc.)
                 version_match = re.search(r'\b(\d+)\b', device_version_str)

            if version_match:
                full_version_str = version_match.group(1)
                try:
                    # Take the first two parts (X.Y) for the float version
                    version_parts = full_version_str.split('.')
                    if len(version_parts) >= 2:
                         self.os_version_float = float(f"{version_parts[0]}.{version_parts[1]}")
                    elif len(version_parts) == 1:
                         self.os_version_float = float(version_parts[0])
                    print(f"[*] Extracted OS Version (approx): {self.os_version_float:.1f} from '{device_version_str}'")
                except ValueError:
                    print(f"[!] Warning: Could not parse version from '{full_version_str}' derived from '{device_version_str}'")
                    self.os_version_float = 0.0 # Reset if parsing fails
            else:
                print(f"[!] Warning: Could not find obvious version pattern in Device Version string '{device_version_str}'")
                self.os_version_float = 0.0 # No version pattern found


        except Exception as parse_e:
             print(f"[!] Overall error during DeviceInfo parsing: {type(parse_e).__name__} - {parse_e}")
             # Fallback: Use USB Vendor ID if full parsing fails significantly
             if self.vendor == "Unknown":
                  self.vendor = self.USB_DEVICE_MAP.get(self.core.dev.idVendor, 'Unknown VendorID')
                  print(f"[*] Falling back to Vendor ID: {self.vendor}")


        print(f"[*] Device Fingerprint (Heuristic Guess):\n"
              f"    Vendor: '{self.vendor}'\n"
              f"    Model: '{self.model}'\n"
              f"    OS ~: Android {self.os_version_float:.1f}\n"
              f"    Serial: '{self.serial}'\n"
              f"    Full Dev Version String: '{device_version_str}'")
        self.device_info_str = repr(devinfo_payload) # Store raw for debugging if needed


    def perform_autopsy(self):
        """Extract device details through MTP GetDeviceInfo."""
        # Attempt to open session first if not already open
        if not self.core.session_id:
             print("[*] No MTP session active. Attempting to open session for reconnaissance...")
             if not self.core.open_session():
                  print("[!] Cannot perform recon: Failed to open MTP session.")
                  # Infer vendor from USB ID as a last resort fallback before giving up
                  if self.core.dev:
                       self.vendor = self.USB_DEVICE_MAP.get(self.core.dev.idVendor, 'Unknown VendorID')
                       print(f"[*] Using USB VendorID as fallback: {self.vendor}")
                  return self.vendor, self.os_version_float # Return defaults/fallbacks


        print("[*] Interrogating device via MTP GetDeviceInfo (OpCode 0x1001)...")
        # GetDeviceInfo transaction: Command (OUT 0x1001), then Data (IN), then Response (IN 0x2001 OK + payload)
        # The execute_transaction needs to handle receiving the Data container before the Response container.
        resp = self.core.execute_transaction(self.core.MTP_OPERATIONS['GetDeviceInfo'])

        if resp and 'final_response' in resp:
             final_resp = resp['final_response']
             final_resp_code = final_resp.get('code')
             final_resp_type = final_resp.get('type') # Should be 3
             devinfo_payload_data = b''

             # Find the DATA container (Type 2) within the received responses, which contains the info payload
             data_response = next((r for r in resp['all_responses'] if r.get('type') == 2), None)

             if final_resp_code == 0x2001 and data_response: # Check if final response is OK AND we got data
                print(f"[+] GetDeviceInfo command successful. Received MTP Data container (Type 2) and final Response (Type 3 Code 0x{final_resp_code:04X}).")
                devinfo_payload_data = data_response.get('payload', b'') # Extract payload from the data container

                if devinfo_payload_data:
                    print(f"[*] Parsing DeviceInfo payload ({len(devinfo_payload_data)} bytes)...")
                    self._parse_device_info(devinfo_payload_data)
                else:
                    print("[!] GetDeviceInfo successful, but no payload received in the Data container.")

             elif final_resp_code == 0x2001 and not data_response:
                 print(f"[!] GetDeviceInfo command successful (Response Code 0x2001), but NO DATA CONTAINER received.")
                 print("    (This might indicate device returned an empty or unexpected MTP flow for GetDeviceInfo)")
                 # Fallback to vendor ID if info wasn't parsed
                 if self.vendor == "Unknown":
                       if self.core.dev:
                            self.vendor = self.USB_DEVICE_MAP.get(self.core.dev.idVendor, 'Unknown VendorID')
                            print(f"[*] Using USB VendorID as fallback: {self.vendor}")

             else:
                 print(f"[!] GetDeviceInfo command failed. Final Response Code: {self.core.get_response_code_name(final_resp_code)} (0x{final_resp_code:04X})")
                 print("    (Common reasons: Session not open, Device busy, Not supported)")
                 # Fallback to vendor ID if info wasn't parsed
                 if self.vendor == "Unknown":
                      if self.core.dev:
                           self.vendor = self.USB_DEVICE_MAP.get(self.core.dev.idVendor, 'Unknown VendorID')
                           print(f"[*] Using USB VendorID as fallback: {self.vendor}")


        else:
            print(f"[!] GetDeviceInfo transaction execution failed. No final response received or transaction structure invalid.")
            # Fallback to vendor ID if info wasn't parsed
            if self.vendor == "Unknown":
                 if self.core.dev:
                      self.vendor = self.USB_DEVICE_MAP.get(self.core.dev.idVendor, 'Unknown VendorID')
                      print(f"[*] Using USB VendorID as fallback: {self.vendor}")


        # Close session now or let __del__ handle it later? Let __del__ for simpler flow,
        # but could explicitly call self.core.close_session() here if preferred.
        # self.core.close_session()

        return self.vendor, self.os_version_float # Return detected (or fallback) info

# ---------- EXPLOIT CHAIN (CONCEPTUAL) -----------
class VoidwalkerEngine:
    def __init__(self, backend):
        # Pass the loaded backend to the MTP core
        self.core = MTPNuclearCore(backend=backend) # This can raise NoBackendError or other USB init errors

        # The _bind_to_darkness call needs to happen *after* the MTPNuclearCore is created
        # to use the self.core object and its backend property, but before recon/ops
        try:
            self.core._bind_to_darkness() # Connect to the USB device/interface
        except SystemExit as e:
            # Re-raise SystemExit messages from _bind_to_darkness directly
            print(e) # Already printed in _bind_to_darkness
            raise # Exit immediately if USB binding fails


        # Now perform recon after successfully binding to a device interface
        self.recon = AndroidRecon(self.core)
        self.vendor, self.os_version = self.recon.perform_autopsy()

        # If recon failed, os_version might be 0.0, vendor "Unknown". Proceed anyway.
        self.oracle = VulnerabilityOracle(self.vendor, self.os_version)
        self.brute_force = ShadowBruteforcer(self.core) # This is just a placeholder now

    def unleash_armageddon(self):
        print(r"""
        ██╗   ██╗ ██████╗ ██╗██████╗ ██╗    ██╗ █████╗ ██╗     ██╗  ██╗███████╗██████╗
        ██║   ██║██╔═══██╗██║██╔══██╗██║    ██║██╔══██╗██║     ██║ ██╔╝██╔════╝██╔══██╗
        ██║   ██║██║   ██║██║██║  ██║██║ █╗ ██║███████║██║     █████╔╝ █████╗  ██████╔╝
        ╚██╗ ██╔╝██║   ██║██║██║  ██║██║███╗██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
         ╚████╔╝ ╚██████╔╝██║██████╔╝╚███╔███╔╝██║  ██║███████╗██║  ██╗███████╗██║  ██║
          ╚═══╝   ╚═════╝ ╚═╝╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                 >>> Android Interaction Framework - MTP Interface <<<
                     !!! Conceptual Framework - Placeholders Included !!!
        """)

        if self.vendor in ["Unknown", "Unknown VendorID"]:
             print("[!] WARNING: Could not reliably identify device vendor during reconnaissance. CVE check might be inaccurate or impossible.")
             print("    (Device info was potentially incomplete or parsing failed.)")


        print(f"[*] Target Heuristics:\n"
              f"    Detected Name: '{self.recon.device_friendly_name}'\n"
              f"    Inferred Vendor: '{self.vendor}'\n"
              f"    Inferred Model: '{self.recon.model}'\n"
              f"    Inferred OS Version ~: {self.os_version:.1f}")

        exploit_cve = self.oracle.get_exploit_path()

        if exploit_cve:
            print(f"\n[*] Potential Vulnerability Identified: {exploit_cve}")
            self._execute_cve_exploit_placeholder(exploit_cve)
            print("\n[!] NOTE: Exploit attempt was a PLACEHOLDER function based on original code.")
            print("      No actual vulnerability was exploited by this script.")

        else:
            print("\n[*] No specific MTP-related CVE identified in the known database for this device/OS profile.")
            print("[*] Proceeding to MTP Brute-Force Simulation (Conceptually Non-Functional)...")
            pin = self.brute_force.execute_silent_brute() # Will print warnings and return None
            if pin:
                 # This code path should NEVER be reached with the current placeholder
                 print(f"\n[+] !! IMPOSSIBLE SUCCESS (SIMULATED): MIRACULOUS UNLOCK !! Simulated PIN: {pin}")
            else:
                 print("\n[-] MTP Brute-Force simulation finished (Ineffective as expected).")
                 self._execute_nuclear_fallback() # Consider DeviceReset

        print("\n--- Voidwalker Execution Flow Complete ---")
        # Cleanup happens automatically via __del__ when the object goes out of scope
        # Or can be explicitly triggered if needed: del voidwalker

    def _execute_cve_exploit_placeholder(self, cve):
        """Manufacturer-specific vulnerability activation (PLACEHOLDER)."""
        print(f"\n[!!!] Executing PLACEHOLDER logic for {cve} - NO ACTUAL EXPLOIT CODE IS HERE [!!!]")
        op_code = None
        # Using fake opcodes as in the original code
        if 'Samsung' in self.vendor: op_code = self.core.MTP_FAKE_EXPLOIT_OPS['Samsung_FakeExploit']
        elif 'HTC' in self.vendor: op_code = self.core.MTP_FAKE_EXPLOIT_OPS['HTC_FakeExploit']
        elif 'Oppo' in self.vendor: op_code = self.core.MTP_FAKE_EXPLOIT_OPS['Oppo_FakeExploit']
        # Add checks for other vendors mapping to potential fake opcodes if defined
        elif 'Google' in self.vendor and 'Pixel' in self.recon.model:
             print("[!] Placeholder: Targeting Google Pixel...")
             # Use a generic fake opcode or add a new one
             op_code = self.core.MTP_FAKE_EXPLOIT_OPS.get('Google_FakeExploit', 0xFAFA) # Example new fake code

        if op_code:
            payload = b'VOIDWALKER_EXPLOIT_SIMULATION_PAYLOAD_' + os.urandom(64) # Dummy payload
            sim_params = (self.core.session_id if self.core.session_id else 0, random.randint(1, 100), len(payload)) # Example dummy params

            print(f"[*] Sending simulated exploit command packet (FAKE OpCode: 0x{op_code:X}, Params={sim_params})...")
            print("    (Device will likely respond with 'Operation Not Supported' or 'Invalid Parameter').")
            # Send the dummy command - THIS DOES NOT EXPLOIT ANYTHING
            response_result = self.core.execute_transaction(op_code, params=sim_params, data_payload=payload) # Include payload simulation

            print(f"[!] Placeholder exploit command transaction complete.")
            if response_result and 'final_response' in response_result:
                 final_resp = response_result['final_response']
                 resp_code = final_resp.get('code')
                 print(f"    Device Final Response Code: {self.core.get_response_code_name(resp_code)} (0x{resp_code:04X})")
                 if resp_code == 0x2004: # Operation Not Supported
                      print("    (Code 0x2004 indicates the device did not recognize the FAKE OpCode, as expected).")
                 elif resp_code == 0x2003: # Parameter Not Supported
                      print("    (Code 0x2003 indicates device did not like the simulated parameters, as expected).")
                 elif resp_code == 0x2001: # OK
                     print("    (Warning: Device returned OK for a FAKE opcode? Highly unusual, maybe misinterpreted!)")
                 else:
                     print("    (Device responded with unexpected code for a FAKE opcode).")

            else:
                print("    [!] No valid final response received from simulated exploit command.")

        else:
            print("[!] No specific placeholder exploit logic defined for the identified vendor/device.")


    def _execute_nuclear_fallback(self):
        """Attempt MTP Device Reset as a last resort."""
        print("\n[!] All other methods simulated or failed.")
        print("[!] Attempting MTP Device Reset (OpCode 0x1011)..")
        print("    !!! WARNING: THIS COMMAND *MAY* INITIATE A FACTORY RESET !!!")
        print("    !!! DATA WILL BE LOST IF THIS COMMAND IS SUPPORTED AND ACCEPTED BY THE DEVICE !!!")
        print("    (Note: This often fails if the device is locked or USB debugging is disabled)")

        # Open session if not already open, necessary for most MTP commands
        if not self.core.session_id:
             print("[*] MTP session not open for DeviceReset attempt. Attempting to open...")
             # Opening session might fail if device is truly unresponsive/locked down
             if not self.core.open_session():
                  print("[!] Failed to open session for DeviceReset attempt. Reset command cancelled.")
                  return # Cannot proceed

        op_code = self.core.MTP_OPERATIONS['DeviceReset'] # 0x1011
        print(f"[*] Sending DeviceReset command (OpCode 0x{op_code:04X}, Session ID {self.core.session_id})...")

        # DeviceReset usually takes no parameters and has no data phase.
        # It might or might not send a Response container before the device resets/disconnects.
        response_result = self.core.execute_transaction(op_code, params=())

        print("[*] DeviceReset command transaction sent.")
        if response_result and 'final_response' in response_result:
            final_resp = response_result['final_response']
            resp_code = final_resp.get('code')
            resp_code_name = self.core.get_response_code_name(resp_code)
            print(f"    Device Final Response Code: {resp_code_name} (0x{resp_code:04X})")

            if resp_code == 0x2001: # OK
                 print("\n[+] MTP DeviceReset command acknowledged successfully by device!")
                 print("    Device should be attempting a factory reset now.")
                 print("    Expect device disconnection soon.")
            elif resp_code == 0x2004: # Operation Not Supported
                 print("[-] MTP DeviceReset is not supported by this device.")
            elif resp_code == 0x2005: # Access Denied
                 print("[-] Access Denied: Device refused the DeviceReset command (often due to screen lock/security policy).")
            elif resp_code == 0x200F: # Session Not Open (Shouldn't happen if open_session succeeded)
                  print("[-] Received 'Session Not Open' error after opening? (Unexpected flow)")
            else:
                 print(f"[-] MTP DeviceReset command failed with response: {resp_code_name} (0x{resp_code:04X})")
                 print("    The device likely did not perform the reset.")
        else:
            print("[!] No final response received for DeviceReset command. Device might reset without confirmation or command was ignored/failed silently.")

        # Note: Don't explicitly close session or dispose here if Reset might succeed.
        # The reset itself disrupts the connection, making cleanup challenging/unnecessary immediately.
        # The __del__ method *will* attempt cleanup anyway if the script exits.

# ---------- RITUAL INVOCATION -----------
if __name__ == "__main__":
    # Call dependency check *first*
    # Note: `check_and_install_dependencies` no longer sys.exits,
    # relies on the import/backend loading block below to handle errors.

    print("Starting Voidwalker v14.88...")
    # We need the pyusb_backend variable defined by the backend loading block above
    # to be available here.

    if pyusb_backend is None:
        print("\n[!] Fatal Error: PyUSB backend could not be loaded. Cannot proceed.")
        print("    Please resolve dependency/backend issues (see messages above).")
        sys.exit(1)


    try:
        # Instantiate the main engine, passing the loaded backend.
        # This will handle binding to the device, reconnaissance, and execution.
        voidwalker = VoidwalkerEngine(backend=pyusb_backend)
        voidwalker.unleash_armageddon() # Runs the main logic

    except usb.core.NoBackendError:
        # This block is a fallback catch, the more specific printout should happen
        # within _bind_to_darkness, but kept here just in case.
         print("-" * 60)
         print("[!!!] FATAL USB ERROR (Caught during Engine Init): No Backend Available [!!!]")
         print("      'pyusb' could not find a library (like libusb) to talk to the USB ports.")
         print("      This might happen if the custom backend loader failed unexpectedly.")
         print("      In Termux: Ensure 'libusb' is installed (`pkg install libusb`) and accessible at")
         print(f"      {TERMIX_LIBUSB_PATH}. Also run 'termux-usb -l' before executing.")
         print("-" * 60)
         sys.exit(1)

    except usb.core.USBError as e:
        print("-" * 60)
        print(f"[!!!] FATAL USB ERROR (Caught during Engine Init or main execution): {type(e).__name__} - {e} [!!!]")
        print("      This is likely a permission issue or device state problem after backend was found.")
        print("      In Termux: Did you run 'termux-usb -l' *before* this script and grant permissions?")
        print("      Ensure cable is stable and device is powered on.")
        print("-" * 60)
        sys.exit(1) # Exit on unrecoverable USB error
    except SystemExit as e:
         print(f"\n[*] Script exited: {e}")
         sys.exit(e.code if isinstance(e, SystemExit) else 1) # Ensure correct exit code if available
    except KeyboardInterrupt:
        print("\n[!] Digital Blood Ritual Aborted by User")
        sys.exit(1) # Indicate abnormal exit due to user
    except Exception as e:
         print("-" * 60)
         print(f"[!!!] UNEXPECTED CRITICAL ERROR during script execution: {type(e).__name__} - {e} [!!!]")
         print("      An unhandled error occurred during MTP operations or logic.")
         import traceback
         traceback.print_exc()
         print("      Please report this traceback.")
         print("-" * 60)
         sys.exit(1) # Indicate fatal error

    # Explicitly delete voidwalker to ensure __del__ runs and cleans up
    del voidwalker
    print("\nScript finished.")