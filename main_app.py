import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QLineEdit, QFileDialog, QMessageBox
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import pygame
import base64
import os
import wave
import json

from network_manager import NetworkManager, HELLO_MSG, READY_MSG, ACK_MSG, NACK_MSG, PORT
from network_manager import NetworkWorkerSignals 

# --- Global Key Management (Only Sender's keys are global as they are fixed for the sender) ---
# Khóa riêng tư và công khai của người gửi
sender_private_key = RSA.generate(2048)
sender_public_key = sender_private_key.publickey()
sender_public_key_pem = sender_public_key.export_key().decode('utf-8')

# Receiver's keys will be generated inside ReceiverApp, not globally here.
# This ensures that the Receiver's actual public key is the one used in the handshake.


# Giao diện Người Gửi (Client)
class SenderApp(QWidget):
    def __init__(self, sender_priv_key): 
        super().__init__()
        self.is_paused = False
        self.setWindowTitle("Người Gửi - Bảo Mật Tin Nhắn Âm Thanh")
        self.setGeometry(100, 100, 500, 400)
        
        # This will be received from the server during handshake
        self.receiver_public_key_from_server = None 
        self.sender_private_key = sender_priv_key
        self.audio_file = None
        
        # Khởi tạo NetworkManager cho Client
        # Đưa khóa công khai của người gửi vào để NetworkManager có thể gửi đi trong handshake
        self.network_manager = NetworkManager(is_server=False, sender_public_key_pem_val=sender_public_key_pem) 
        
        self._handshake_step1_completed = False # Flag để theo dõi bước 1 handshake (nhận READY_MSG và khóa công khai của server)
        self._sent_pub_key = False # Flag để theo dõi đã gửi khóa công khai của mình chưa
        self.init_ui()
        self._connect_signals()

        # Khởi động NetworkManager sau một khoảng trễ nhỏ để UI kịp khởi tạo
        QTimer.singleShot(100, self.network_manager.start)

    def init_ui(self):
        layout = QVBoxLayout()

        self.network_status_label = QLabel("Trạng thái mạng: Đang khởi động...", self)
        self.network_status_label.setStyleSheet("font-weight: bold; color: blue;")
        layout.addWidget(self.network_status_label)
        
        self.metadata_label = QLabel("Nhập Metadata (ví dụ: ID và thời gian):", self)
        self.metadata_input = QLineEdit(self)
        self.metadata_input.setPlaceholderText("VD: User1, 2023-10-27 15:30:00")
        layout.addWidget(self.metadata_label)
        layout.addWidget(self.metadata_input)

        self.select_file_btn = QPushButton('Chọn Tệp Âm Thanh', self)
        self.select_file_btn.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_btn)

        self.selected_file_label = QLabel("Chưa chọn tệp âm thanh.", self)
        layout.addWidget(self.selected_file_label)

        self.send_pub_key_btn = QPushButton("Gửi Khóa Công Khai Của Bạn", self)
        self.send_pub_key_btn.clicked.connect(self.send_sender_public_key)
        self.send_pub_key_btn.setEnabled(False) # Ban đầu vô hiệu hóa cho đến khi handshake thành công
        layout.addWidget(self.send_pub_key_btn)

        self.encrypt_btn = QPushButton('Mã Hóa Tin Nhắn và Gửi Qua Mạng', self)
        self.encrypt_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 10px; border-radius: 5px;")
        self.encrypt_btn.clicked.connect(self.encrypt_and_send_message)
        self.encrypt_btn.setEnabled(False) # Ban đầu vô hiệu hóa cho đến khi khóa công khai của sender được gửi
        layout.addWidget(self.encrypt_btn)

        self.result_label = QLabel("Kết quả sẽ xuất hiện ở đây.", self)
        self.result_label.setAlignment(Qt.AlignCenter)
        self.result_label.setStyleSheet("color: blue; font-style: italic;")
        layout.addWidget(self.result_label)

        layout.addStretch()
        self.setLayout(layout)

    def _connect_signals(self):
        # Kết nối tín hiệu từ NetworkManager tới các slot của SenderApp
        self.network_manager.signals.update_status.connect(self.update_network_status_label)
        self.network_manager.signals.response_ack_nack.connect(self.handle_ack_nack_response)
        self.network_manager.signals.receiver_pub_key_received.connect(self.set_receiver_public_key) 

    def update_network_status_label(self, message):
        self.network_status_label.setText(f"Trạng thái mạng: {message}")
        
    def set_receiver_public_key(self, pub_key_pem):
        """Slot nhận khóa công khai của người nhận từ NetworkManager."""
        try:
            self.receiver_public_key_from_server = RSA.import_key(pub_key_pem)
            self._handshake_step1_completed = True
            self.network_status_label.setText(f"Trạng thái mạng: Đã nhận khóa công khai của người nhận. Sẵn sàng gửi khóa của bạn.")
            self.send_pub_key_btn.setEnabled(True) # Kích hoạt nút gửi khóa công khai của sender
        except Exception as e:
            QMessageBox.critical(self, "Lỗi Khóa", f"Không thể nhập khóa công khai của người nhận: {e}")
            self.network_status_label.setText("Trạng thái mạng: Lỗi khóa công khai người nhận.")

    def send_sender_public_key(self):
        """Gửi khóa công khai của người gửi tới server."""
        if self.network_manager.connection and self.network_manager.running and self.receiver_public_key_from_server:
            pub_key_data = {
                "type": "public_key_exchange",
                "public_key": sender_public_key_pem # Sử dụng khóa công khai của người gửi đã định nghĩa global
            }
            if self.network_manager.request_send_data(json.dumps(pub_key_data)):
                self.update_network_status_label("Đã yêu cầu gửi khóa công khai của bạn, chờ phản hồi...")
                self.send_pub_key_btn.setEnabled(False) # Vô hiệu hóa nút để tránh gửi lại
                self.encrypt_btn.setEnabled(False) # Tạm thời vô hiệu hóa nút mã hóa
            else:
                QMessageBox.warning(self, "Lỗi", "Không thể gửi yêu cầu gửi khóa công khai. Mạng có thể đang bận hoặc bị lỗi.")
        else:
            QMessageBox.warning(self, "Lỗi", "Chưa kết nối đến người nhận, mạng đang đóng, hoặc chưa nhận được khóa công khai của người nhận.")

    def handle_ack_nack_response(self, is_ack, message_str):
        """Xử lý phản hồi ACK/NACK từ server."""
        if is_ack:
            self.result_label.setText(f"<font color='green'>Đã nhận ACK: {message_str}</font>")
            if not self._sent_pub_key: # Nếu đây là phản hồi ACK cho việc gửi khóa công khai của sender
                self._sent_pub_key = True
                self.send_pub_key_btn.setEnabled(False) 
                self.encrypt_btn.setEnabled(True) # Kích hoạt nút mã hóa
            else: # Nếu là ACK cho tin nhắn đã mã hóa
                self.encrypt_btn.setEnabled(True) # Kích hoạt lại nút mã hóa để gửi tin khác (nếu muốn)
        else:
            self.result_label.setText(f"<font color='red'>Đã nhận NACK hoặc lỗi: {message_str}</font>")
            QMessageBox.critical(self, "Lỗi Gửi/Nhận", f"Lỗi trong quá trình gửi hoặc nhận phản hồi: {message_str}")
            if not self._sent_pub_key: # Nếu NACK khi gửi khóa
                self.send_pub_key_btn.setEnabled(True) # Kích hoạt lại nút gửi khóa
            else: # Nếu NACK khi gửi tin nhắn
                self.encrypt_btn.setEnabled(True) # Kích hoạt lại nút mã hóa


    def select_file(self):
        """Cho phép người dùng chọn tệp âm thanh WAV."""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Chọn Tệp Âm Thanh", "", "Audio Files (*.wav);;All Files (*)", options=options)
        if file_name:
            try:
                # Kiểm tra xem có phải tệp WAV hợp lệ không
                with wave.open(file_name, 'rb') as wf:
                    pass
                self.audio_file = file_name
                self.selected_file_label.setText(f"Đã chọn tệp: <b>{os.path.basename(file_name)}</b>")
                self.result_label.setText("Sẵn sàng mã hóa.")
            except wave.Error:
                QMessageBox.critical(self, "Lỗi Tệp", "Tệp đã chọn không phải là tệp WAV hợp lệ.")
                self.audio_file = None
                self.selected_file_label.setText("Chưa chọn tệp âm thanh.")
        else:
            self.selected_file_label.setText("Chưa chọn tệp âm thanh.")

    def encrypt_and_send_message(self):
        """Mã hóa tin nhắn âm thanh và gửi đi."""
        try:
            metadata = self.metadata_input.text().strip().encode('utf-8')
            if not metadata:
                QMessageBox.warning(self, "Lỗi", "Vui lòng nhập metadata.")
                return

            if not self.audio_file:
                QMessageBox.warning(self, "Lỗi", "Vui lòng chọn tệp âm thanh.")
                return
            
            # Đảm bảo đã nhận được khóa công khai của người nhận và đã kết nối
            if not self.receiver_public_key_from_server:
                QMessageBox.warning(self, "Lỗi", "Chưa nhận được khóa công khai của người nhận. Vui lòng hoàn tất handshake.")
                return

            if not self.network_manager.connection or not self.network_manager.running:
                QMessageBox.warning(self, "Lỗi", "Chưa kết nối đến người nhận hoặc mạng đang đóng. Vui lòng kết nối trước.")
                return

            self.result_label.setText("Đang xử lý và gửi...")
            QApplication.processEvents()

            # Đọc dữ liệu âm thanh gốc
            with open(self.audio_file, 'rb') as audio_file:
                original_audio_data = audio_file.read()

            # --- Mã hóa DES ---
            des_key = get_random_bytes(8) # Tạo khóa DES ngẫu nhiên (8 bytes cho DES)
            cipher_des = DES.new(des_key, DES.MODE_CBC) # Khởi tạo đối tượng DES với chế độ CBC
            # Mã hóa dữ liệu âm thanh và thêm IV vào phía trước của ciphertext
            encrypted_audio_with_iv = cipher_des.iv + cipher_des.encrypt(pad(original_audio_data, DES.block_size))

            # --- Mã hóa khóa DES bằng RSA (OAEP) ---
            # Sử dụng khóa công khai của người nhận đã nhận được từ server
            cipher_rsa = PKCS1_OAEP.new(self.receiver_public_key_from_server)
            encrypted_des_key = cipher_rsa.encrypt(des_key)

            # --- Tạo Hash của CIPHERTEXT và Chữ ký số trên Hash đó ---
            hash_of_ciphertext = SHA256.new(encrypted_audio_with_iv) # Tính hash của CIPHERTEXT
            signer = pkcs1_15.new(self.sender_private_key) # Khởi tạo đối tượng ký với khóa riêng của người gửi
            signature_on_ciphertext = signer.sign(hash_of_ciphertext) # Ký hash của CIPHERTEXT

            # --- Tạo gói dữ liệu để gửi đi ---
            # Tuân thủ cấu trúc gói dữ liệu của đề bài
            encrypted_package = {
                "cipher": base64.b64encode(encrypted_audio_with_iv).decode('utf-8'), # Dữ liệu âm thanh đã mã hóa
                "hash": base64.b64encode(hash_of_ciphertext.digest()).decode('utf-8'), # Hash của ciphertext
                "sig": base64.b64encode(signature_on_ciphertext).decode('utf-8'),      # Chữ ký của hash ciphertext
                "encrypted_des_key": base64.b64encode(encrypted_des_key).decode('utf-8'), # Khóa DES đã mã hóa
                "metadata": base64.b64encode(metadata).decode('utf-8') # Metadata (chưa ký riêng theo đề bài, nhưng có thể thêm "signed_info" nếu cần)
            }
            
            # Yêu cầu NetworkManager gửi gói dữ liệu
            if self.network_manager.request_send_data(json.dumps(encrypted_package)):
                self.result_label.setText("Tin nhắn đã được yêu cầu gửi, chờ phản hồi...")
                self.encrypt_btn.setEnabled(False) # Vô hiệu hóa nút gửi trong khi chờ phản hồi
            else:
                self.result_label.setText(f"<font color='red'>Lỗi: Không thể yêu cầu gửi tin nhắn.</font>")
                QMessageBox.critical(self, "Lỗi", "Không thể yêu cầu gửi tin nhắn.")

        except FileNotFoundError:
            QMessageBox.critical(self, "Lỗi", "Không tìm thấy tệp âm thanh đã chọn.")
            self.result_label.setText("<font color='red'>Lỗi: Không tìm thấy tệp âm thanh.</font>")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi Mã hóa/Gửi", f"Đã xảy ra lỗi: {e}")
            self.result_label.setText(f"<font color='red'>Đã xảy ra lỗi: {e}</font>")

    def closeEvent(self, event):
        """Xử lý sự kiện đóng ứng dụng."""
        self.network_manager.stop() # Đảm bảo dừng luồng mạng
        super().closeEvent(event)


# Giao diện Người Nhận (Server)
class ReceiverApp(QWidget):
    def __init__(self): 
        super().__init__()
        self.setWindowTitle("Người Nhận - Bảo Mật Tin Nhắn Âm Thanh")
        self.setGeometry(650, 100, 500, 400)
        
        # Tạo khóa riêng tư và công khai của người nhận
        self.receiver_private_key = RSA.generate(2048)
        self.receiver_public_key = self.receiver_private_key.publickey()
        self.receiver_public_key_pem = self.receiver_public_key.export_key().decode('utf-8')

        # Khởi tạo NetworkManager cho Server
        # Đưa khóa công khai của người nhận vào để NetworkManager có thể gửi nó đi trong handshake
        self.network_manager = NetworkManager(is_server=True, receiver_public_key_pem_val=self.receiver_public_key_pem) 
        
        self.current_encrypted_package = None # Lưu trữ gói tin mã hóa nhận được
        self._handshake_started = False # Flag để theo dõi trạng thái handshake

        self.init_ui()
        self._connect_signals()
        pygame.mixer.init() # Khởi tạo mixer để phát âm thanh

        # Khởi động NetworkManager sau một khoảng trễ nhỏ
        QTimer.singleShot(100, self.network_manager.start)
        
    def init_ui(self):
        layout = QVBoxLayout()

        self.network_status_label = QLabel("Trạng thái mạng: Đang khởi động...", self)
        self.network_status_label.setStyleSheet("font-weight: bold; color: green;")
        layout.addWidget(self.network_status_label)

        self.metadata_display_label = QLabel("Metadata: Chưa có", self)
        self.metadata_display_label.setStyleSheet("font-weight: bold; color: #555;")
        layout.addWidget(self.metadata_display_label)

        self.decrypt_btn = QPushButton('Giải Mã Tin Nhắn và Phát', self)
        self.decrypt_btn.setStyleSheet("background-color: #008CBA; color: white; font-weight: bold; padding: 10px; border-radius: 5px;")
        self.decrypt_btn.clicked.connect(self.decrypt_message)
        self.decrypt_btn.setEnabled(False) # Ban đầu vô hiệu hóa cho đến khi nhận được tin nhắn
        layout.addWidget(self.decrypt_btn)

        self.play_pause_btn = QPushButton('Dừng Phát Nhạc', self)
        self.play_pause_btn.setStyleSheet("background-color: #f44336; color: white; font-weight: bold; padding: 10px; border-radius: 5px;")
        self.play_pause_btn.clicked.connect(self.toggle_play_pause)
        self.play_pause_btn.setEnabled(False)  # BReceiverApp an đầu vô hiệu hóa, chỉ bật sau khi nhạc được phát
        layout.addWidget(self.play_pause_btn)

        self.result_label = QLabel("Kết quả sẽ xuất hiện ở đây.", self)
        self.result_label.setAlignment(Qt.AlignCenter)
        self.result_label.setStyleSheet("color: blue; font-style: italic;")
        layout.addWidget(self.result_label)
        
        layout.addStretch()
        self.setLayout(layout)

    def toggle_play_pause(self):
        """Điều khiển việc phát và dừng nhạc."""
        if pygame.mixer.music.get_busy():  # Kiểm tra xem nhạc có đang phát không
            pygame.mixer.music.pause()  # Tạm dừng nhạc
            self.result_label.setText("<font color='orange'>Đã tạm dừng phát.</font>")
            self.play_pause_btn.setText("Phát lại")
        else:
            pygame.mixer.music.unpause()  # Phát lại nhạc
            self.result_label.setText("<font color='green'>Đang phát lại...</font>")
            self.play_pause_btn.setText("Dừng phát")


    def _connect_signals(self):
        # Kết nối tín hiệu từ NetworkManager tới các slot của ReceiverApp
        self.network_manager.signals.update_status.connect(self.update_network_status_label)
        self.network_manager.signals.message_received.connect(self.handle_received_message_from_signal)

    def update_network_status_label(self, message):
        self.network_status_label.setText(f"Trạng thái mạng: {message}")
        if "Sẵn sàng nhận tin nhắn mã hóa." in message and not self._handshake_started:
            self._handshake_started = True


    def handle_received_message_from_signal(self, encrypted_package):
        """Xử lý gói tin mã hóa nhận được từ NetworkManager."""
        self.current_encrypted_package = encrypted_package
        self.update_network_status_label("Đã nhận được tin nhắn mã hóa! Nhấn 'Giải Mã' để xem.")
        self.decrypt_btn.setEnabled(True) # Kích hoạt nút giải mã

        try:
            # Hiển thị metadata (nếu có)
            metadata_bytes = base64.b64decode(encrypted_package.get("metadata", ""))
            self.metadata_display_label.setText(f"Metadata: <b>{metadata_bytes.decode('utf-8')}</b>")
        except Exception:
            self.metadata_display_label.setText("Metadata: Không đọc được hoặc bị hỏng")

    def decrypt_message(self):
        """Giải mã, xác thực và phát lại tin nhắn âm thanh."""
        if not hasattr(self, 'current_encrypted_package') or not self.current_encrypted_package:
            QMessageBox.warning(self, "Lỗi", "Chưa có tin nhắn mã hóa nào để giải mã!")
            return
        
        # Đảm bảo đã nhận được khóa công khai của người gửi để xác thực chữ ký
        if not self.network_manager.sender_public_key_for_verification: 
            QMessageBox.warning(self, "Lỗi", "Chưa nhận được khóa công khai của người gửi để xác thực chữ ký!")
            return

        try:
            self.result_label.setText("Đang giải mã và xác thực...")
            QApplication.processEvents()

            # Lấy các thành phần từ gói tin nhận được (đã điều chỉnh tên khóa theo đề bài)
            encrypted_audio_with_iv = base64.b64decode(self.current_encrypted_package["cipher"]) # Dữ liệu đã mã hóa
            signature_from_sender = base64.b64decode(self.current_encrypted_package["sig"]) # Chữ ký trên hash của ciphertext
            hash_from_sender = base64.b64decode(self.current_encrypted_package["hash"])   # Hash của ciphertext từ người gửi
            encrypted_des_key = base64.b64decode(self.current_encrypted_package["encrypted_des_key"])

            # --- BƯỚC 1: GIẢI MÃ KHÓA DES BẰNG RSA (OAEP) ---
            cipher_rsa = PKCS1_OAEP.new(self.receiver_private_key) # Sử dụng khóa riêng của người nhận
            des_key = cipher_rsa.decrypt(encrypted_des_key)

            # --- BƯỚC 2: KIỂM TRA HASH CỦA CIPHERTEXT (Trước khi giải mã dữ liệu âm thanh) ---
            # Tính hash của ciphertext mà người nhận vừa nhận được
            calculated_hash_of_ciphertext = SHA256.new(encrypted_audio_with_iv) 

            # So sánh hash người gửi đã gửi với hash vừa tính được
            if hash_from_sender != calculated_hash_of_ciphertext.digest():
                QMessageBox.critical(self, "Lỗi Toàn vẹn", "Lỗi: Hash của ciphertext không khớp! Dữ liệu có thể đã bị giả mạo hoặc thay đổi trong quá trình truyền.")
                self.result_label.setText("<font color='red'>Lỗi: Hash của ciphertext không đúng!</font>")
                self.network_manager.send_data(NACK_MSG) # Gửi NACK nếu hash không khớp
                return

            # --- BƯỚC 3: XÁC THỰC CHỮ KÝ SỐ TRÊN HASH CỦA CIPHERTEXT ---
            try:
                verifier = pkcs1_15.new(self.network_manager.sender_public_key_for_verification) # Sử dụng khóa công khai của người gửi
                verifier.verify(calculated_hash_of_ciphertext, signature_from_sender) # Xác thực chữ ký với hash của CIPHERTEXT

                QMessageBox.information(self, "Xác thực Chữ ký", "Chữ ký số đã được xác thực thành công! Tin nhắn xác thực từ người gửi.")
                # Nếu xác thực thành công, sẽ tiếp tục giải mã và phát nhạc
            except (ValueError, TypeError) as e:
                QMessageBox.critical(self, "Lỗi Xác thực Chữ ký", f"Chữ ký số không hợp lệ hoặc đã bị giả mạo! Tin nhắn không đáng tin cậy. Lỗi: {e}")
                self.result_label.setText("<font color='red'>Lỗi: Chữ ký số không hợp lệ!</font>")
                self.network_manager.send_data(NACK_MSG) # Gửi NACK nếu chữ ký không hợp lệ
                return

            # --- BƯỚC 4: GIẢI MÃ ÂM THANH BẰNG DES (Chỉ khi hash và chữ ký hợp lệ) ---
            # Tách IV và ciphertext
            iv = encrypted_audio_with_iv[:DES.block_size]
            ciphertext_content = encrypted_audio_with_iv[DES.block_size:]

            cipher_des = DES.new(des_key, DES.MODE_CBC, iv)
            decrypted_audio_data = unpad(cipher_des.decrypt(ciphertext_content), DES.block_size)

            # Lưu tệp âm thanh đã giải mã
            output_audio_file = 'decrypted_audio.wav'
            with open(output_audio_file, 'wb') as output_file:
                output_file.write(decrypted_audio_data)

            # Phát lại âm thanh
            try:
                pygame.mixer.music.load(output_audio_file)
                pygame.mixer.music.play()
                self.result_label.setText("<font color='green'>Giải mã thành công và chữ ký đã được xác thực! Đang phát lại âm thanh...</font>")
                self.play_pause_btn.setEnabled(True)
                self.network_manager.send_data(ACK_MSG) # Gửi ACK sau khi tất cả các bước đều thành công
            except pygame.error as pyg_err:
                QMessageBox.critical(self, "Lỗi Phát Âm Thanh", f"Không thể phát tệp âm thanh. Đảm bảo tệp WAV hợp lệ: {pyg_err}")
                self.result_label.setText("<font color='orange'>Giải mã thành công nhưng không thể phát âm thanh.</font>")
                self.network_manager.send_data(NACK_MSG) # Gửi NACK nếu không thể phát âm thanh (lỗi về định dạng file)
        
        except ValueError as ve:
            # Lỗi giá trị thường do giải mã RSA hoặc DES thất bại (khóa sai, dữ liệu hỏng)
            QMessageBox.critical(self, "Lỗi Giải mã", f"Lỗi giá trị trong quá trình giải mã: {ve}. Có thể khóa không đúng hoặc dữ liệu bị hỏng.")
            self.result_label.setText(f"<font color='red'>Lỗi giá trị: {ve}</font>")
            self.network_manager.send_data(NACK_MSG) # Gửi NACK
        except Exception as e:
            # Các lỗi khác không xác định
            QMessageBox.critical(self, "Lỗi Giải mã", f"Đã xảy ra lỗi không xác định trong quá trình giải mã: {e}")
            self.result_label.setText(f"<font color='red'>Đã xảy ra lỗi: {e}</font>")
            self.network_manager.send_data(NACK_MSG) # Gửi NACK
    
    def stop_audio(self):
        """Dừng phát nhạc."""
        if pygame.mixer.music.get_busy():
            pygame.mixer.music.stop()
            self.result_label.setText("<font color='orange'>Âm thanh đã được dừng.</font>")
            self.stop_btn.setEnabled(False)
    

    def closeEvent(self, event):
        """Xử lý sự kiện đóng ứng dụng."""
        self.network_manager.stop() # Đảm bảo dừng luồng mạng
        pygame.mixer.quit() # Giải phóng tài nguyên pygame mixer
        super().closeEvent(event)


# Khối thực thi chính của ứng dụng
if __name__ == '__main__':
    app = QApplication(sys.argv)

    is_server_mode = False
    # Kiểm tra đối số dòng lệnh để xác định chế độ chạy (server hoặc client)
    if len(sys.argv) > 1 and sys.argv[1].lower() == '--server':
        is_server_mode = True
        print("Chạy ứng dụng ở chế độ NGƯỜI NHẬN (SERVER).")
    elif len(sys.argv) > 1 and sys.argv[1].lower() == '--client':
        print("Chạy ứng dụng ở chế độ NGƯỜI GỬI (CLIENT).")
    else:
        print("Vui lòng chạy với đối số: '--server' (Người Nhận) hoặc '--client' (Người Gửi).")
        sys.exit(1) # Thoát nếu không có đối số hợp lệ

    if is_server_mode:
        window_receiver = ReceiverApp() 
        window_receiver.show()
    else:
        window_sender = SenderApp(sender_private_key) 
        window_sender.show()

    sys.exit(app.exec_()) # Bắt đầu vòng lặp sự kiện của PyQt