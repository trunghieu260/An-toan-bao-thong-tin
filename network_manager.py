import socket
import threading
import json
import base64
import time
from PyQt5.QtCore import pyqtSignal, QObject 
from Crypto.PublicKey import RSA 
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Các hằng số cho việc giao tiếp
HELLO_MSG = "Hello!"  
READY_MSG = "Ready!"  
ACK_MSG = "ACK" 
NACK_MSG = "NACK" 
PORT = 12345 
BUFFER_SIZE = 4096

# Lớp tín hiệu cho các thao tác mạng, sẽ được sử dụng trong PyQt để phát tín hiệu giao tiếp UI
class NetworkWorkerSignals(QObject):
    update_status = pyqtSignal(str)  
    message_received = pyqtSignal(dict)
    response_ack_nack = pyqtSignal(bool, str) 
    receiver_pub_key_received = pyqtSignal(str)  

# Lớp quản lý kết nối mạng (client/server)
class NetworkManager:
    def __init__(self, is_server=False, host='127.0.0.1', port=PORT, 
                 receiver_public_key_pem_val=None, sender_public_key_pem_val=None): 
        self.host = host
        self.port = port
        self.is_server = is_server
        self.socket = None
        self.connection = None
        self.address = None
        self.running = False

        self.connected_event = threading.Event()
        self.send_request_event = threading.Event()  
        self.data_to_send = None  # Dữ liệu cần gửi

        self.signals = NetworkWorkerSignals()  # Khởi tạo tín hiệu

        self.receiver_public_key_pem_val = receiver_public_key_pem_val
        self.sender_public_key_pem_val = sender_public_key_pem_val 

        self.sender_public_key_for_verification = None  #

    def _send_to_ui(self, message):
        # Gửi thông báo đến UI
        print(f"[Network] {message}")
        self.signals.update_status.emit(message) 

    def start(self):
        self.running = True
        self._send_to_ui(f"Đang khởi động chế độ {'SERVER' if self.is_server else 'CLIENT'}...")
        if self.is_server:
    
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
        else:
            self.client_thread = threading.Thread(target=self._run_client)
            self.client_thread.daemon = True
            self.client_thread.start()

    def stop(self):
        # Dừng kết nối
        if not self.running:
            return
        self._send_to_ui("Đang đóng kết nối mạng...")
        self.running = False
        self.connected_event.clear()
        self.send_request_event.clear() 

        # Đóng kết nối
        if self.connection:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            except OSError as e:
                self._send_to_ui(f"Lỗi khi đóng kết nối: {e}")
            finally:
                self.connection = None
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except OSError as e:
                self._send_to_ui(f"Lỗi khi đóng socket lắng nghe: {e}")
            finally:
                self.socket = None
        self._send_to_ui("Kết nối đã đóng.")

    def _run_server(self):
        # Xử lý kết nối cho server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.socket.bind((self.host, self.port))  # Gắn cổng và địa chỉ cho server
            self.socket.listen(1)  # Lắng nghe kết nối
            self._send_to_ui(f"Máy chủ đang lắng nghe trên {self.host}:{self.port}...")
            
            self.connection, self.address = self.socket.accept()  # Chấp nhận kết nối từ client
            self._send_to_ui(f"Đã kết nối từ: {self.address}")
            self.connected_event.set()

            # Xử lý handshake với client
            self._handle_server_handshake()
            
            # Lắng nghe tin nhắn mã hóa từ client
            self._listen_for_encrypted_messages()

        except OSError as e:
            self._send_to_ui(f"Lỗi khởi động máy chủ hoặc kết nối: {e}")
        except Exception as e:
            self._send_to_ui(f"Lỗi không xác định ở Server: {e}")
        finally:
            self.stop()

    def _run_client(self):
        # Xử lý kết nối cho client
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._send_to_ui(f"Client đang cố gắng kết nối tới {self.host}:{self.port}...")
            self.socket.connect((self.host, self.port))
            self.connection = self.socket
            self.address = self.socket.getpeername()
            self._send_to_ui(f"Đã kết nối tới server: {self.address}")
            self.connected_event.set()

            # Thực hiện handshake với server
            self._handle_client_handshake() 
            self._wait_for_send_requests()  # Đợi yêu cầu gửi dữ liệu

        except ConnectionRefusedError:
            self._send_to_ui("Kết nối bị từ chối. Đảm bảo server đang chạy.")
        except OSError as e:
            self._send_to_ui(f"Lỗi kết nối client: {e}")
        except Exception as e:
            self._send_to_ui(f"Lỗi không xác định ở Client: {e}")
        finally:
            self.stop()

    # Hàm xử lý handshake cho client
    def _handle_client_handshake(self):
        self.send_data(HELLO_MSG)  # Gửi thông báo hello
        self._send_to_ui("Đã gửi 'Hello!', chờ phản hồi...")
        response = self.receive_data()  # Nhận phản hồi
        if response:
            try:
                response_data = json.loads(response.decode('utf-8'))
                if response_data.get("type") == "handshake" and response_data.get("message") == READY_MSG:
                    received_pub_key_pem = response_data.get("public_key")
                    if received_pub_key_pem:
                        # Phát tín hiệu cho UI biết đã nhận khóa công khai
                        self.signals.receiver_pub_key_received.emit(received_pub_key_pem)
                        self._send_to_ui(f"Handshake thành công! Đã nhận khóa công khai người nhận.")
                    else:
                        self._send_to_ui("Handshake lỗi: Không nhận được khóa công khai của người nhận.")
                        self.stop()
                else:
                    self._send_to_ui(f"Handshake lỗi: Phản hồi không hợp lệ: {response_data}")
                    self.stop()
            except json.JSONDecodeError:
                self._send_to_ui(f"Handshake lỗi: Phản hồi không phải JSON: {response.decode('utf-8')}")
                self.stop()
        else:
            self._send_to_ui("Handshake lỗi: Không nhận được phản hồi từ người nhận.")
            self.stop()

    # Hàm xử lý handshake cho server
    def _handle_server_handshake(self):
        request = self.receive_data()
        if request and request.decode('utf-8') == HELLO_MSG:
            self._send_to_ui("Đã nhận 'Hello!' từ người gửi. Đang gửi 'Ready!' và khóa công khai.")

            if not self.receiver_public_key_pem_val:
                self._send_to_ui("Lỗi: Khóa công khai của người nhận chưa được cung cấp cho NetworkManager.")
                self.stop()
                return

            response_data = {
                "type": "handshake",
                "message": READY_MSG,
                "public_key": self.receiver_public_key_pem_val 
            }
            if self.send_data(json.dumps(response_data)):
                self._send_to_ui("Handshake thành công! Chờ khóa công khai của người gửi...")

                sender_key_response = self.receive_data()
                if sender_key_response:
                    try:
                        key_data = json.loads(sender_key_response.decode('utf-8'))
                        if key_data.get("type") == "public_key_exchange" and key_data.get("public_key"):
                            # Lưu khóa công khai của người gửi để xác thực sau này
                            self.sender_public_key_for_verification = RSA.import_key(key_data.get("public_key"))
                            self._send_to_ui(f"Đã nhận khóa công khai của người gửi: {key_data.get('public_key')[:30]}...")
                            self._send_to_ui("Sẵn sàng nhận tin nhắn mã hóa.")
                            self.send_data(ACK_MSG) 
                        else:
                            self._send_to_ui("Lỗi: Dữ liệu khóa công khai người gửi không hợp lệ.")
                            self.send_data(NACK_MSG)
                            self.stop()
                    except json.JSONDecodeError:
                        self._send_to_ui("Lỗi: Dữ liệu khóa công khai người gửi không phải JSON.")
                        self.send_data(NACK_MSG)
                        self.stop()
                else:
                    self._send_to_ui("Lỗi: Không nhận được khóa công khai của người gửi.")
                    self.send_data(NACK_MSG)
                    self.stop()
            else:
                self._send_to_ui("Lỗi khi gửi 'Ready!' trong handshake.")
                self.stop()
        else:
            self._send_to_ui("Lỗi: Không nhận được 'Hello!' hợp lệ từ người gửi.")
            self.stop()

    # Gửi dữ liệu tới đối tác
    def send_data(self, data):
        if not self.connection or not self.running:
            self._send_to_ui("Lỗi: Chưa có kết nối hoặc mạng không hoạt động để gửi dữ liệu.")
            return False
        try:
            data_bytes = data.encode('utf-8') if isinstance(data, str) else data
            length_prefix = len(data_bytes).to_bytes(4, 'big')  # Tiền tố chiều dài dữ liệu
            self.connection.sendall(length_prefix + data_bytes)
            return True
        except OSError as e:
            self._send_to_ui(f"Lỗi gửi dữ liệu: {e}")
            self.stop()
            return False

    # Nhận dữ liệu từ đối tác
    def receive_data(self):
        if not self.connection or not self.running:
            return None
        try:
            length_prefix = self.connection.recv(4)
            if not length_prefix:
                self._send_to_ui("Kết nối đã đóng bởi đối phương.")
                self.stop()
                return None
            
            data_length = int.from_bytes(length_prefix, 'big')

            data_parts = []
            bytes_recd = 0
            while bytes_recd < data_length:
                chunk = self.connection.recv(min(data_length - bytes_recd, BUFFER_SIZE))
                if not chunk:
                    self._send_to_ui("Kết nối bị mất khi đang nhận dữ liệu.")
                    self.stop()
                    return None
                data_parts.append(chunk)
                bytes_recd += len(chunk)
            
            return b"".join(data_parts)
        except OSError as e:
            if self.running:
                self._send_to_ui(f"Lỗi nhận dữ liệu: {e}")
            self.stop()
            return None
        except Exception as e:
            self._send_to_ui(f"Lỗi không xác định khi nhận dữ liệu: {e}")
            self.stop()
            return None

    # Hàm chờ và xử lý các yêu cầu gửi dữ liệu
    def _wait_for_send_requests(self):
        while self.running:
            self.send_request_event.wait()  # Chờ sự kiện gửi yêu cầu
            if not self.running:
                break
            
            if self.data_to_send:
                self._send_to_ui("Đang gửi dữ liệu theo yêu cầu từ UI...")
                sent_ok = self.send_data(self.data_to_send)
                self.data_to_send = None 

                if sent_ok:
                    response = self.receive_data()
                    if response:
                        message = response.decode('utf-8')
                        is_ack = (message == ACK_MSG)
                        self.signals.response_ack_nack.emit(is_ack, message)
                    else:
                        self.signals.response_ack_nack.emit(False, "Không nhận được phản hồi sau khi gửi.")
                else:
                    self.signals.response_ack_nack.emit(False, "Gửi dữ liệu thất bại.")
            self.send_request_event.clear()

    # Lắng nghe các tin nhắn mã hóa
    def _listen_for_encrypted_messages(self):
        while self.running:
            self._send_to_ui("Đang chờ tin nhắn mã hóa...")
            encrypted_message_raw = self.receive_data()
            if encrypted_message_raw:
                try:
                    encrypted_package = json.loads(encrypted_message_raw.decode('utf-8'))
                    self.signals.message_received.emit(encrypted_package) 
                except json.JSONDecodeError:
                    self._send_to_ui("Lỗi: Tin nhắn nhận được không phải định dạng JSON.")
                    self.send_data(NACK_MSG) 
                except Exception as e:
                    self._send_to_ui(f"Lỗi xử lý tin nhắn nhận được: {e}")
                    self.send_data(NACK_MSG) 
            else:
                self._send_to_ui("Kết nối đã mất hoặc ngừng hoạt động.")
                break 

    # Yêu cầu gửi dữ liệu
    def request_send_data(self, data):
        if not self.running:
            self._send_to_ui("Không thể gửi yêu cầu: NetworkManager không hoạt động.")
            self.signals.response_ack_nack.emit(False, "NetworkManager không hoạt động.")
            return False
        
        self.data_to_send = data 
        self.send_request_event.set()  # Gửi sự kiện yêu cầu gửi dữ liệu
        return True
