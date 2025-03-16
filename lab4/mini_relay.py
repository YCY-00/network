import random
import struct
import logging
import threading
import socket
import select
import mini_crypt
import mini_cell
from os.path import join

MAX_INCOMING_CONNECTION = 5
VERSIONS_BODY = 3

CELL_CIRCID_LEN = 2
CELL_CMD_LEN = 1
LEN_OF_CELL_VARIABLE_BODY_LEN = 2
CELL_FIXED_BODY_LEN = 1024

# cell_commands
CELL_CMD_CREATE = 1
CELL_CMD_CREATED = 2
CELL_CMD_RELAY = 3
CELL_CMD_DESTROY = 4
CELL_CMD_VERSIONS = 7
CELL_CMD_NETINFO = 8
CELL_CMD_CERTS = 129

# relay_commands:
RELAY_CMD_BEGIN = 1
RELAY_CMD_DATA = 2
RELAY_CMD_END = 3
RELAY_CMD_CONNECTED = 4
RELAY_CMD_EXTEND = 6
RELAY_CMD_EXTENDED = 7


DH_PUB_NUM_LEN = 128

DH_G = 2
DH_P = int("BC6E230F63512CB36605599417DE96B6DE189B93E63250EFAF457462533D8EBB"
           "EF362F478BDBDAEB4E0726F4102F54F6B58CB70C5257A829456D981A2E5FCD7B",
           16)


def read_PEM_file(file_path):
    data = b''
    with open(file_path, 'rb') as file_path:
        for line in file_path: data += line
    return data

def verify_or_descriptor(body:str) -> tuple[str, str, int, mini_crypt.RSAPublicKey]:
    lines = body.split('\r\n')
    or_name = ''
    or_addr = ''
    or_port = ''
    or_pubk = None
    or_msg = ''
    or_sign_len = 0
    or_sign = b''
    for line in lines:
        if 'NICKNAME:' in line:
            or_msg += line + '\r\n'
            or_name = line.strip().split('NICKNAME:', 1)[1]
        elif 'ADDRESS:' in line: 
            or_msg += line + '\r\n'
            or_addr_port = line.strip().split('ADDRESS:', 1)[1]
            or_addr = or_addr_port.split(':')[0]
            or_port = or_addr_port.split(':')[1]
        elif 'PUBLIC_K:' in line:
            or_msg += line + '\r\n'
            or_pubk = mini_crypt.deserialize_public_key_from_bytes(line.strip().split('PUBLIC_K:', 1)[1].encode('utf-8'))
        elif 'SIGN_LEN:' in line:
            or_sign_len = int(line.strip().split('SIGN_LEN:', 1)[1])
        elif 'SIGNATURE:' in line:
            or_sign = line.strip().split('SIGNATURE:', 1)[1][:or_sign_len*2]
    or_msg = or_msg.encode('utf-8')
    or_sign = bytes.fromhex(or_sign)
    if not mini_crypt.RSA_verify_sign(or_pubk, or_msg, or_sign):
        raise Exception('verify_or_descriptor(): OR\' signature is invalid')
    return or_name, or_addr, int(or_port), or_pubk

def verify_auth_signature(body:str, auth_pub_k, message:bytes):
    auth_sign_len = 0
    auth_sign = b''
    lines = body.split('\r\n')
    for line in lines:
        if line.startswith('AUTH_SIGN_LEN:'):
            auth_sign_len = int(line.split(':', 1)[1])
        elif line.startswith('AUTH_SIGNATURE:'):
            if auth_sign_len == 0: 
                raise Exception('check_auth_signature(): No AUTH_SIGN_LEN in the body')
            auth_sign = line.split('AUTH_SIGNATURE:', 1)[1][:auth_sign_len*2]
            break
    else: 
        raise Exception('check_auth_signature(): either no AUTH_SIGN_LEN or no AUTH_SIGNATURE')

    auth_sign = bytes.fromhex(auth_sign)
    if not mini_crypt.RSA_verify_sign(auth_pub_k, message, auth_sign):
        raise Exception('check_auth_signature(): Incorrect authority\'s signature')
    else: return True

def handle_descriptors_from_auth(response, auth_pub_k):
    dict_descriptors = {}
    descriptors = ''
    auth_signature = ''
    body = response.strip().split('\r\n\r\n', 1)[1]
    sign_chunks = body.split('\r\n\r\n')
    for chunk in sign_chunks:
        if chunk.startswith('NICKNAME:'):
            descriptors += chunk + '\r\n\r\n'
            or_name, or_addr, or_port, or_pubk = verify_or_descriptor(chunk)
            dict_descriptors[or_name] = {
                'or_ip': or_addr, 
                'or_port': or_port, 
                'or_pubk': or_pubk,
            }
        elif chunk.startswith('AUTH_SIGN_LEN:'):
            auth_signature = chunk
    verify_auth_signature(auth_signature, auth_pub_k, descriptors.encode('utf-8'))
    return dict_descriptors


class Relay(threading.Thread):
    def __init__(
            self, 
            ip,
            port, 
            auth_ip,
            auth_port, 
            nickname,
            circ_id_base,
            auth_public_key_path = 'Authority.pub',
    ):
        super().__init__()
        self.ip = ip
        self.port = port
        self.running = True
        self.auth_ip = auth_ip
        self.auth_port = auth_port
        self.nickname = nickname
        self.circ_id_base = circ_id_base

        self.dict_descriptors = {}
        self.sock_list = []
        # You may declare your own data structure here

        self.setup_logger()

        self.logger.info(f'\n\n\n\nstarting new run! initialize...')
        keys_dir = join(join('data', nickname), 'keys')
        self.public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(join(keys_dir, nickname+'.pub')))
        self.private_key = mini_crypt.deserialize_private_key_from_bytes(read_PEM_file(join(keys_dir, nickname)))
        self.auth_public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(join(keys_dir, auth_public_key_path)))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # to ignore TIME_WAIT for the sake of ease.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.ip, self.port))
        self.sock.listen(MAX_INCOMING_CONNECTION)
        self.sock_list.append(self.sock)

    def setup_logger(self):
        home_dir = join('data', self.nickname)
        filename = join(home_dir, self.nickname+'.log')
        self.logger = logging.getLogger(self.nickname)
        handler = logging.FileHandler(filename)
        fmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(fmtr)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    # This is not necessary when we are opening the socket in the real world, but this is 
    # here only to demonstrate the anonymization of ip addresses. You should use this 
    # method when you are trying to connect to other onion routers and web server.
    def open_new_sock(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.ip, 0))
        return sock

    # You should use this method to accept incomming connnections, else the thread will 
    # not terminate properly.
    def socket_accept(self):
        while self.running:
            readable, _, _ = select.select([self.sock], [], [], 0.5)
            if self.sock in readable:
                sock, addr = self.sock.accept()
                return sock, addr
        return None, None

    # You should use this method to accept incomming connnections, else the thread will 
    # not terminate properly.
    def get_header(self, sock):
        while self.running:
            readable, _, _ = select.select([sock], [], [], 0.5)
            if sock in readable:
                header = sock.recv(CELL_CIRCID_LEN+CELL_CMD_LEN)
                if len(header) < CELL_CIRCID_LEN+CELL_CMD_LEN:
                    sock.close()
                    raise Exception(f'get_header(): failed to receive {CELL_CIRCID_LEN+CELL_CMD_LEN} bytes')
                cell_circ_id, cell_command = struct.unpack('!HB', header)
                return cell_circ_id, cell_command
        return None, None

    # You should use this method to recv from socket, else the thread will not terminate 
    # properly.
    def get_variable_length_body(self, sock):
        while self.running:
            readable, _, _ = select.select([sock], [], [], 0.5)
            if sock in readable:
                cell_body_len = sock.recv(LEN_OF_CELL_VARIABLE_BODY_LEN)
                if len(cell_body_len) < LEN_OF_CELL_VARIABLE_BODY_LEN:
                    sock.close()
                    raise Exception(f'get_variable_length_body(): failed to receive {LEN_OF_CELL_VARIABLE_BODY_LEN} bytes')
                cell_body_len = struct.unpack('!H', cell_body_len)[0]
                cell_body = sock.recv(cell_body_len)
                return cell_body_len, cell_body
        return None, None

    # You should use this method to recv from socket, else the thread will not terminate 
    # properly.
    def get_fixed_length_body(self, sock):
        while self.running:
            readable, _, _ = select.select([sock], [], [], 0.5)
            if sock in readable:
                cell_body = sock.recv(CELL_FIXED_BODY_LEN)
                if len(cell_body) < CELL_FIXED_BODY_LEN:
                    sock.close()
                    raise Exception(f'get_fixed_length_body(): failed to receive {CELL_FIXED_BODY_LEN} bytes')
                return cell_body
        return None

    def run(self):
        sock, addr = self.socket_accept()
        circ_id, cell_command = self.get_header(sock)

        # TODO task1: Accept channel open request. 
        # When an onion router receives a VERSIONS cell, it replies VERIONS, CERTS, NETINFO 
        # cell. Then, it waits for NETINFO cell to finish the handshake to open channel

        # VERSIONS 수신
        self.sock_list.append(sock)
        length, body = self.get_variable_length_body(sock)
        recieved_versions = mini_cell.VERSIONS.from_bytes(body, length)

        # VERSIONS 송신
        valid_versions = list(set(recieved_versions.versions_list) & set([3]))  # 공통 version 획득
        sent_versions = mini_cell.VERSIONS(valid_versions)
        sock.sendall(sent_versions.to_bytes())

        # CERTS 송신
        pem = mini_crypt.serialize_public_key_into_bytes(self.public_key)  # 공개 키 pem data 생성
        signature = mini_crypt.RSA_sign_msg(self.private_key, pem)  # 비밀 키와 pem data를 사용하여 signature 생성
        sent_certs = mini_cell.CERTS(pem, signature)
        sock.sendall(sent_certs.to_bytes())

        # NETINFO 송신
        my_address = f"{self.ip}:{self.port}".encode('utf-8')  # address 양식: '<ip>:<port>'
        peer_address = f"{addr[0]}:{addr[1]}".encode('utf-8')
        sent_netinfo = mini_cell.NETINFO(len(peer_address), peer_address, len(my_address), my_address)
        sock.sendall(sent_netinfo.to_bytes())

        # NETINFO 수신
        self.get_header(sock)
        _, body = self.get_variable_length_body(sock)
        recieved_netinfo = mini_cell.NETINFO.from_bytes(body)

        # ip 주소 확인
        my_address = f"{self.ip}:{self.port}".encode('utf-8')  # address 양식: '<ip>:<port>'
        if my_address != recieved_netinfo.peer_addr:
            raise Exception("router's ip address is not match")
        # print("NETINFO-relay")

        # TODO task1: Accept circuit open request. 
        # When an onion router receives a CREATE cell, it derives a shared secret key, 
        # then it replies CREATED cell with the public key (public number) and a signature
        # attached to it. The client then can derive the identical shared secret key with
        # the public key (public number).

        # CREATE 수신 및 공유 숫자 생성
        self.get_header(sock)
        length, body = self.get_variable_length_body(sock)
        recieved_create = mini_cell.CREATE.from_bytes(body, circ_id)
        decrypted_public_num = mini_crypt.RSA_decrypt_msg(self.private_key, recieved_create.encryted_DH_public_key)
        peer_public_num = int(decrypted_public_num.decode('utf-8'), 16)

        # 공유 키 생성
        dh_private_key, dh_public_key = mini_crypt.DH_gen_key_pair(DH_G, DH_P)  # dh_비밀 키와 dh_공개 키 생성
        self.derived_key = mini_crypt.DH_derive_shared_key(DH_G, DH_P, dh_private_key, peer_public_num)  # 공유 키 저장(router는 client와의 공유 키 1개만 필요)
        # print(self.nickname, ":", self.derived_key)
        # print("Make derived_key-relay")

        # dh 공개 숫자 및 서명 생성
        dh_public_num = mini_crypt.DH_gen_public_num(dh_public_key)
        hex_public_num = format(dh_public_num, 'x').encode('utf-8')
        signature = mini_crypt.RSA_sign_msg(self.private_key, hex_public_num)

        # CREATED 송신
        sent_created = mini_cell.CREATED(circ_id, hex_public_num, signature)
        sock.sendall(sent_created.to_bytes())

        # TODO task2: Extend circuit. 
        # When an router receives a RELAY cell it decrypt it with the shared secret key. 
        # if the onion router recognizes the cell, it checks the relay command and behave 
        # accordinglly.
        # If the RELAY cell has EXTEND command, the cell should have the following:
        #   1) the next hop onion router's nickname, and
        #   2) the client's Diffie-Hellman public number encrypted with the next hop's 
        # public key.
        # The onion router tries to open up channel to the next hop onion router (just 
        # like client did: send VERSIONS, recv VERSIONS, CERTS, NETINFO, send NETINFO).
        # After the channel is opened, the initiating onion router sends CREATE cell to 
        # the next-hop onion router (initiating onion router is the one who first sends
        # VERSIONS cell). The CREATE cell's body should be the encrypted Diffie-Hellman 
        # public number sent by the client (the RELAY-EXTEND cell). When the initiating 
        # onion router receives CREATED cell, the initiating onion router packs the 
        # CREATED cell's body into a RELAY cell with EXTENDED command and sends it back to 
        # the client to indicate the circuit has been extended. 
        while self.running:
            circ_id, cell_command = self.get_header(sock)
            if cell_command == CELL_CMD_RELAY:
                # Relay Cell 수신
                body = self.get_fixed_length_body(sock)
                recieved_relay = mini_cell.RELAY.from_bytes(body, circ_id)

                # 복호화
                decrypted_relay, is_endpoint = recieved_relay.decrypt(self.derived_key)
                # print(self.nickname, decrypted_relay.recognized, decrypted_relay.digest, decrypted_relay.data_length)

                # recognized extend 획득
                if is_endpoint and decrypted_relay.relay_command == RELAY_CMD_EXTEND:

                    # 채널 설정
                    extend_data = mini_cell.RELAY_EXTEND.from_bytes(decrypted_relay.data)
                    next_hop_name = extend_data.or_name.decode('utf-8')
                    next_hop = self.dict_descriptors[next_hop_name]
                    next_hop_ip = next_hop['or_ip']
                    next_hop_port = next_hop['or_port']
                    self.next_hop_sock = self.open_new_sock()
                    self.next_hop_sock.connect((next_hop_ip, next_hop_port))
                    self.circ_id = random.randint(self.circ_id_base, self.circ_id_base + 999)

                    # VERSIONS 송신
                    sent_versions = mini_cell.VERSIONS([3])  # lab에서는 version 3만 지원
                    self.next_hop_sock.sendall(sent_versions.to_bytes())

                    # VERSIONS 수신
                    self.get_header(self.next_hop_sock)
                    length, body = self.get_variable_length_body(self.next_hop_sock)
                    recieved_versions = mini_cell.VERSIONS.from_bytes(body, length)

                    if len(recieved_versions.versions_list) == 0:
                        raise Exception("There is no valid version")
                    protocol_version = recieved_versions.versions_list[-1]  # 오름차순 정렬이라 가정할 때, 가장 최신 버전
                    # print("versions:", protocol_version)

                    # CERTS 수신
                    self.get_header(self.next_hop_sock)
                    body = self.get_fixed_length_body(self.next_hop_sock)
                    recieved_certs = mini_cell.CERTS.from_bytes(body)

                    # signature 인증
                    next_hop_pubk = next_hop['or_pubk']
                    mini_crypt.RSA_verify_sign(next_hop_pubk, recieved_certs.PEM, recieved_certs.signature)  # 정상이면 True, 아니면 raise
                    # print("CERTS")

                    # NETINFO 수신
                    self.get_header(self.next_hop_sock)
                    _, body = self.get_variable_length_body(self.next_hop_sock)
                    recieved_netinfo = mini_cell.NETINFO.from_bytes(body)

                    # ip 주소 확인
                    my_address = f"{self.ip}:{self.next_hop_sock.getsockname()[1]}".encode('utf-8')
                    peer_address = f"{next_hop_ip}:{next_hop_port}".encode('utf-8')  # 회로의 첫 or = relay node
                    if my_address != recieved_netinfo.peer_addr:
                        print(my_address, recieved_netinfo.peer_addr)
                        raise Exception("client's ip address is not match")
                    # print("NETINFO-client")

                    # NETINFO 송신
                    my_addr_len = len(my_address)
                    peer_addr_len = len(peer_address)
                    sent_netinfo = mini_cell.NETINFO(peer_addr_len, peer_address, my_addr_len, my_address)
                    self.next_hop_sock.sendall(sent_netinfo.to_bytes())

                    # CREATE cell 송신(client 값 사용)
                    sent_create = mini_cell.CREATE(self.circ_id, extend_data.encrypted_DH_public_key)
                    self.next_hop_sock.sendall(sent_create.to_bytes())

                    # CREATED cell 수신
                    self.get_header(self.next_hop_sock)
                    _, body = self.get_variable_length_body(self.next_hop_sock)
                    recieved_created = mini_cell.CREATED.from_bytes(body, self.circ_id)
                    mini_crypt.RSA_verify_sign(next_hop_pubk, recieved_created.DH_public_key, recieved_created.signature)  # 정상이면 True, 아니면 raise

                    # RELAY-EXTENDED 송신
                    extended_data = mini_cell.RELAY_EXTENDED(recieved_created.DH_public_key, recieved_created.signature).to_bytes()
                    relay_extended = mini_cell.RELAY(circ_id, RELAY_CMD_EXTENDED, 0, 0, len(extended_data), extended_data)
                    relay_extended.update_digest()
                    encrypted_relay = relay_extended.encrypt(self.derived_key)
                    sock.sendall(encrypted_relay.to_bytes())
                    # print("connect:", next_hop_name)

        # TODO task2: Extend circuit. 
        # When an router receives a RELAY cell it decrypt it with the shared secret key. 
        # If the router does not recognize the cell, the router relays it to the next-hop 
        # onion router.
                # 복호화 X
                elif not is_endpoint:
                    # 다음 노드로 전송
                    decrypted_relay.circ_id = self.circ_id  # circuit id update
                    self.next_hop_sock.sendall(decrypted_relay.to_bytes())

                    # task 4: relay-end는 반환 X
                    # 응답 대기 후 이전 노드로 전송(client가 최종 목적이므로 digest 확인 필요 X)
                    _, command = self.get_header(self.next_hop_sock)
                    body = self.get_fixed_length_body(self.next_hop_sock)
                    if command == CELL_CMD_RELAY:
                        relay_extended = mini_cell.RELAY.from_bytes(body, circ_id)
                        encrypted_relay = relay_extended.encrypt(self.derived_key)
                        sock.sendall(encrypted_relay.to_bytes())

        # TODO task3: Connect to web server. 
        # When an onion router receives a RELAY cell with BEGIN command, it opens up the 
        # connection to the destination web server which is written in the RELAY-BEGIN 
        # cell. After the connection is accepted by the web server, the onion router 
        # replies RELAY cell with CONNECTED command. 

                # RELAY BEGIN 수신
                elif is_endpoint and decrypted_relay.relay_command == RELAY_CMD_BEGIN:
                    # 소켓 연결
                    begin_data = mini_cell.RELAY_BEGIN.from_bytes(decrypted_relay.data)
                    web_addr = begin_data.target_addr.decode('utf-8')
                    web_ip, web_port = web_addr.split(":")
                    self.web_sock = self.open_new_sock()
                    self.web_sock.connect((web_ip, int(web_port)))

                    # RELAY-CONNECTED 전송
                    relay_connected = mini_cell.RELAY(circ_id, RELAY_CMD_CONNECTED, 0, 0, len(decrypted_relay.data), decrypted_relay.data)
                    relay_connected.update_digest()
                    encrypted_relay = relay_connected.encrypt(self.derived_key)
                    sock.sendall(encrypted_relay.to_bytes())

        # TODO task3: Send (and receive) data to (and from) the web server.
        # When an onion router receives RELAY cell with DATA command, it sends the 
        # unmodified data to the web server. When the web server replies some data, the 
        # router packs it into a RELAY cell with DATA command and sends it back to the 
        # client.
                elif is_endpoint and decrypted_relay.relay_command == RELAY_CMD_DATA:

                    # RELAY-DATA 수신 및 HTTP request 송신
                    self.web_sock.sendall(decrypted_relay.data)

                    # HTTP response 수신 및 RELAY-DATA 송신
                    web_response = self.web_sock.recv(1024)  # HTTP 기본 길이
                    relay_data = mini_cell.RELAY(circ_id, RELAY_CMD_DATA, 0, 0, len(web_response), web_response)
                    relay_data.update_digest()
                    encrypted_relay = relay_data.encrypt(self.derived_key)
                    sock.sendall(encrypted_relay.to_bytes())

        # TODO task4: Close connection with web server.
        # When an onion router receives RELAY cell with END command, it closes the socket
        # that is used to communicate with the web server.
                elif is_endpoint and decrypted_relay.relay_command == RELAY_CMD_END:
                    self.web_sock.close()
                    del self.web_sock  # 속성 제거로 연결 오류 방지
                    # print("end web")

        # TODO task4: Close circuit.
        # When an onion router receives DESTROY cell, it closes the socket that is used 
        # to communicate with the client (or an initiating onion router). If there is a 
        # next-hop onion router, it sends DESTROY cell to the onion router and closes the 
        # socket that is used to communicate with the next-hop onion router. 
            # relay cell이 아닌 경우 종료
            else:
                break

        if cell_command == CELL_CMD_DESTROY:
            # print("start destroy")
            sock.close()
            if hasattr(self, 'next_hop_sock'):  # 마지막 라우터는 next_hop_sock X
                sent_destroy= mini_cell.DESTROY(self.circ_id).to_bytes()
                self.next_hop_sock.sendall(sent_destroy)
                del self.next_hop_sock  # 속성을 완전히 지워 연결 오류 대비
                # print("close ", self.nickname)

    def fetch_descriptors_from_auth(self):
        sock = self.open_new_sock()
        sock.connect((self.auth_ip, self.auth_port))

        self.logger.info(f'connected to authority, sending request for the descriptors..')
        request = (
            f'GET /tor/server/all HTTP/1.1\r\n'
            f'Host: {self.auth_ip}:{self.auth_port}\r\n'
            f'Content-Type: text/plain\r\n'
            f'Content-Length: {0}\r\n\r\n'
        )
        sock.sendall(request.encode('utf-8'))
        response = sock.recv(4096).decode('utf-8')

        self.logger.info(f'got response: {response}')
        self.dict_descriptors = handle_descriptors_from_auth(response, self.auth_public_key)
        self.logger.info(self.dict_descriptors)
        sock.close()

    def register_to_authority(self):
        public_PEM = (mini_crypt.serialize_public_key_into_bytes(self.public_key)).decode('utf-8')
        descriptor = 'NICKNAME:' + self.nickname + '\r\n' \
                    + 'ADDRESS:' + str(self.ip) + ':' + str(self.port) + '\r\n' \
                    + 'PUBLIC_K:' + public_PEM + '\r\n'
        sign = mini_crypt.RSA_sign_msg(self.private_key, descriptor.encode('utf-8'))
        descriptor += 'SIGN_LEN:' + str(len(sign)) + '\r\n' \
                    + 'SIGNATURE:' + sign.hex() + '\r\n'
        request_line = 'POST /tor/ HTTP/1.1\r\n'
        headers = (
            f'Host: {self.auth_ip}:{self.auth_port}\r\n'
            f'Content-Type: text/plain\r\n'
            f'Content-Length: {len(descriptor)}\r\n'
            '\r\n'
        )
        request = request_line + headers + descriptor
        sock = self.open_new_sock()
        sock.connect((self.auth_ip, self.auth_port))
        sock.sendall(request.encode('utf-8'))
        response = sock.recv(4096).decode('utf-8')
        self.logger.debug(f'got response from auth: {response}')
        # TODO: check authority's signature
        self.logger.info(f'successfully registered')
        sock.close()

    def stop(self):
        self.logger.info(f'stop() is called!')
        self.running = False

    def cleanup(self):
        self.logger.info(f'cleanup(): cleaning up relay on port {self.port}')
        for sock in self.sock_list:
            sock.close()
        self.sock.close()
