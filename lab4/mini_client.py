import struct
import threading
import socket
import logging
import select
import mini_crypt
import mini_cell
from os.path import join

MAX_INCOMING_CONNECTION = 5
VERSIONS_BODY = 3

CIRCID_LEN = 2
COMMAND_LEN = 1
CELL_LENGTH = 2
CELL_BODY_LEN = 1024


CREATE_CELL = 1
CREATED_CELL = 2
RELAY_CELL = 3
DESTROY_CELL = 4
VERSIONS_CELL = 7
NETINFO_CELL = 8
CERTS_CELL = 129

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
        raise Exception('verify_or_descriptor(): OR\'s signature is invalid')
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

class Onion_client(threading.Thread):
    def __init__(
            self, 
            ip,
            auth_ip,
            auth_port,
            nickname,
            web_server_ip,
            web_server_port,
            circ_id,
            circuit_or_names = None,
            auth_public_key_path = 'Authority.pub',
    ):
        super().__init__()
        self.ip = ip
        self.running = True
        self.auth_ip = auth_ip
        self.auth_port = auth_port
        self.nickname = nickname
        self.circ_id = circ_id

        self.dict_descriptors = {}
        self.circuit = []
        self.sock = None
        self.web_server_ip = web_server_ip
        self.web_server_port = web_server_port
        self.circuit_or_names = circuit_or_names
        self.setup_logger()

        self.logger.info(f'\n\n\n\nstarting new run! initialize...')
        keys_dir = join(join('data', nickname), 'keys')
        self.public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(join(keys_dir, nickname+'.pub')))
        self.private_key = mini_crypt.deserialize_private_key_from_bytes(read_PEM_file(join(keys_dir, nickname)))
        self.auth_public_key = mini_crypt.deserialize_public_key_from_bytes(read_PEM_file(join(keys_dir, auth_public_key_path)))

    def setup_logger(self):
        home_dir = join('data', self.nickname)
        filename = join(home_dir, self.nickname+'.log')
        self.logger = logging.getLogger(self.nickname)
        handler = logging.FileHandler(filename)
        fmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(fmtr)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

    def open_new_sock(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # This is not necessary when we are opening the socket in the real world, 
        # but this is here only to demonstrate the anonymization of ip addresses.
        sock.bind((self.ip, 0))
        return sock

    def run(self):
        self.logger.info(f'entered run(), now start running')
        self.fetch_descriptors_from_auth()

        if self.circuit_or_names != None:
            self.constitute_circuit_path(self.circuit_or_names)
        else: return
        # the method for task1
        self.connect_to_first_router()

        # the method for task2:
        self.extend_circuit()

        # the method for task3:
        self.connect_to_web_server_via_circuit()

        # the method for task4:
        self.end_connection_to_web_server()
        self.destroy_circuit()

        self.cleanup()
        return

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

    def constitute_circuit_path(self, circuit_or_names):
        for or_name in circuit_or_names:
            or_ip = self.dict_descriptors[or_name]['or_ip']
            or_port = self.dict_descriptors[or_name]['or_port']
            or_pubk = self.dict_descriptors[or_name]['or_pubk']
            self.circuit.append({
                'or_name': or_name,
                'or_ip': or_ip,
                'or_port': or_port,
                'or_pubk': or_pubk,
                'DH_private_key': None,
                'symmetric_key': None,
            })

    # You should use this method to accept incomming connnections, else the thread will 
    # not terminate properly.
    def get_header(self, sock):
        while self.running:
            readable, _, _ = select.select([sock], [], [], 0.5)
            if sock in readable:
                header = sock.recv(CIRCID_LEN+COMMAND_LEN)
                if len(header) < CIRCID_LEN+COMMAND_LEN:
                    sock.close()
                    raise Exception(f'get_header(): failed to receive {CIRCID_LEN+COMMAND_LEN} bytes')
                cell_circ_id, cell_command = struct.unpack('!HB', header)
                return cell_circ_id, cell_command
        return None, None

    # You should use this method to recv from socket, else the thread will not terminate 
    # properly.
    def get_variable_length_body(self, sock):
        while self.running:
            readable, _, _ = select.select([sock], [], [], 0.5)
            if sock in readable:
                cell_body_len = sock.recv(CELL_LENGTH)
                if len(cell_body_len) < CELL_LENGTH:
                    sock.close()
                    raise Exception(f'get_variable_length_body(): failed to receive {CELL_LENGTH} bytes')
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
                cell_body = sock.recv(CELL_BODY_LEN)
                if len(cell_body) < CELL_BODY_LEN:
                    sock.close()
                    raise Exception(f'get_fixed_length_body(): failed to receive {CELL_BODY_LEN} bytes')
                return cell_body
        return None

    def connect_to_first_router(self):
        # Open socket to the first onion router of the circuit
        self.sock = self.open_new_sock()
        # TODO task1: Open channel to the first hop. Send VERSIONS cell and receive 
        # VERSIONS, CERTS, and NETINFO cell. Send NETINFO cell to finish handshake.

        # first hop 연결
        first_hop = self.circuit[0]
        self.sock.connect((first_hop['or_ip'], first_hop['or_port']))

        # VERSIONS 송신
        sent_versions = mini_cell.VERSIONS([3])  # lab에서는 version 3만 지원
        self.sock.sendall(sent_versions.to_bytes())

        # VERSIONS 수신
        self.get_header(self.sock)
        length, body = self.get_variable_length_body(self.sock)
        recieved_versions = mini_cell.VERSIONS.from_bytes(body, length)

        if len(recieved_versions.versions_list) == 0:
            raise Exception("There is no valid version")
        protocol_version = recieved_versions.versions_list[-1]  # 오름차순 정렬이라 가정할 때, 가장 최신 버전
        # print("versions:", protocol_version)

        # CERTS 수신
        self.get_header(self.sock)
        body = self.get_fixed_length_body(self.sock)
        recieved_certs = mini_cell.CERTS.from_bytes(body)

        # signature 인증
        first_hop_pubk = first_hop['or_pubk']
        mini_crypt.RSA_verify_sign(first_hop_pubk, recieved_certs.PEM, recieved_certs.signature)  # 정상이면 True, 아니면 raise
        # print("CERTS")

        # NETINFO 수신
        self.get_header(self.sock)
        _, body = self.get_variable_length_body(self.sock)
        recieved_netinfo = mini_cell.NETINFO.from_bytes(body)

        # ip 주소 확인
        my_address = f"{self.ip}:{self.sock.getsockname()[1]}".encode('utf-8')
        peer_address = f"{self.circuit[0]['or_ip']}:{self.circuit[0]['or_port']}".encode('utf-8')  # 회로의 첫 or = relay node
        if my_address != recieved_netinfo.peer_addr:
            print(my_address, recieved_netinfo.peer_addr)
            raise Exception("client's ip address is not match")
        # print("NETINFO-client")

        # NETINFO 송신
        my_addr_len = len(my_address)
        peer_addr_len = len(peer_address)
        sent_netinfo = mini_cell.NETINFO(peer_addr_len, peer_address, my_addr_len, my_address)
        self.sock.sendall(sent_netinfo.to_bytes())

        #TODO task1: Open circuit to the first hop. Send CREATE cell and receive CREATED 
        # cell to derive a shared secret key.

        # dh_공개 키 암호화
        dh_private_key, dh_public_key = mini_crypt.DH_gen_key_pair(DH_G, DH_P)  # dh_비밀 키와 dh_공개 키 생성
        dh_public_num = mini_crypt.DH_gen_public_num(dh_public_key)
        hex_public_num = format(dh_public_num, 'x').encode('utf-8')
        encrypted_public_num = mini_crypt.RSA_encrypt_msg(first_hop_pubk, hex_public_num)

        # CREATE cell 송신
        sent_create = mini_cell.CREATE(self.circ_id, encrypted_public_num)
        self.sock.sendall(sent_create.to_bytes())

        # CREATED cell 수신
        circ_id, _ = self.get_header(self.sock)
        _, body = self.get_variable_length_body(self.sock)
        recieved_created = mini_cell.CREATED.from_bytes(body, circ_id)
        mini_crypt.RSA_verify_sign(first_hop_pubk, recieved_created.DH_public_key, recieved_created.signature)  # 정상이면 True, 아니면 raise

        # 공유 키 생성
        peer_public_num = int(recieved_created.DH_public_key.decode('utf-8'), 16)
        derived_key = mini_crypt.DH_derive_shared_key(DH_G, DH_P, dh_private_key, peer_public_num)
        first_hop['derived_key'] = derived_key  # dervie_shared_key는 상대 라우터의 dh_public_key가 필요하므로, CREATED 단계에서 저장 필요

    def extend_circuit(self):
        sock = self.sock

        # TODO task2: Extend circuit. Send RELAY cell with EXTEND command to the first 
        # onion router, and let the first onion router to extend the circuit. In order to 
        # do so the EXTEND-RELAY cell should have the following: 
        #   1) The next hop onion router's nickname
        #   2) The client's Diffie-Hellman public number encrypted with the next hop's 
        # public key
        # After the RELAY-EXTEND cell is generated, the client should encrypt the RELAY 
        # cell with the derived shared secret key. For example, if the client is asking 
        # second-hop onion router to extend the circuit, the RELAY cell should be 
        # encrypted with the secret key shared between the first onion router and the 
        # secret key shared between the second onion router. 
        # Once the RELAY-EXTEND cell is sent, wait for the RELAY cell with EXTENDED 
        # command sent by the first onion router. Then derive the shared secret key with 
        # the seconde onion router. Repeat the process to extend the circuit to third hop.

        # 회로 내 router에 대해 순차적으로 channel 확장(N = len(self.circuit))
        for i in range(len(self.circuit) - 1):
            next_hop = self.circuit[i + 1]

            # dh_public_key 암호화(이전 router와의 derieved_key 저장 필요 -> circuit dict에 저장?)
            dh_private_key, dh_public_key = mini_crypt.DH_gen_key_pair(DH_G, DH_P)  # 라우터마다 dh_pair를 바꾸어 보안 강화
            dh_public_num = mini_crypt.DH_gen_public_num(dh_public_key)
            hex_public_num = format(dh_public_num, 'x').encode('utf-8')
            encrypted_public_num = mini_crypt.RSA_encrypt_msg(next_hop['or_pubk'], hex_public_num)

            # RELAY 생성
            next_hop_name = next_hop['or_name'].encode('utf-8')
            extend_data = mini_cell.RELAY_EXTEND(len(next_hop_name), next_hop_name, encrypted_public_num).to_bytes()
            relay_extend = mini_cell.RELAY(self.circ_id, RELAY_CMD_EXTEND, 0, 0, len(extend_data), extend_data)
            relay_extend.update_digest()

            # 암호화 및 RELAY-EXTEDN 송신
            for j in range(i + 1):  # target까지의 모든 router, 역순으로 암호화
                relay_extend = relay_extend.encrypt(self.circuit[i - j]['derived_key'])
            sock.sendall(relay_extend.to_bytes())

            # RELAY-EXTENDED 수신
            circ_id, _ = self.get_header(sock)
            body = self.get_fixed_length_body(sock)
            relay_extended = mini_cell.RELAY.from_bytes(body, circ_id)

            # M 번 복호화
            for j in range(i + 1):  # target까지의 모든 router, 정순으로 복호화
                relay_extended, is_endpoint = relay_extended.decrypt(self.circuit[j]['derived_key'])
            if not is_endpoint:
                raise Exception("RELAY-EXTENDED CELL is modified")
            extended_data = mini_cell.RELAY_EXTENDED.from_bytes(relay_extended.data)

            # next_hop에 대한 공유 키 생성 및 저장
            peer_dh_pubk = extended_data.DH_public_key
            mini_crypt.RSA_verify_sign(next_hop['or_pubk'], peer_dh_pubk, extended_data.signature)  # 정상이면 True, 아니면 raise

            peer_public_num = int(peer_dh_pubk.decode('utf-8'), 16)
            derived_key = mini_crypt.DH_derive_shared_key(DH_G, DH_P, dh_private_key, peer_public_num)
            next_hop['derived_key'] = derived_key  # dervie_shared_key는 상대 라우터의 dh_public_key가 필요하므로, CREATED 단계에서 저장 필요
            # print(next_hop_name, ":", derived_key)

    def connect_to_web_server_via_circuit(self):
        sock = self.sock
        # TODO task3: Reach web server via the constructed circuit. Send RELAY cell with 
        # BEGIN command to the third (last) onion router. Wait for the RELAY cell with the 
        # CONNECTED command

        # RELAY BEGIN 생성
        web_address = f"{self.web_server_ip}:{self.web_server_port}".encode('utf-8')
        begin_data = mini_cell.RELAY_BEGIN(len(web_address), web_address).to_bytes()
        relay_begin = mini_cell.RELAY(self.circ_id, RELAY_CMD_BEGIN, 0, 0, len(begin_data), begin_data)
        relay_begin.update_digest()

        # 암호화 및 RELAY-BEGIN 송신
        N = len(self.circuit)
        for i in range(N):  # target까지의 모든 router, 역순으로 암호화
            relay_begin = relay_begin.encrypt(self.circuit[N - 1 - i]['derived_key'])
        sock.sendall(relay_begin.to_bytes())

        # RELAY-CONNECTED 수신
        circ_id, _ = self.get_header(sock)
        body = self.get_fixed_length_body(sock)
        relay_connected = mini_cell.RELAY.from_bytes(body, circ_id)

        for i in range(N):  # target까지의 모든 router, 정순으로 복호화
            relay_connected, is_endpoint = relay_connected.decrypt(self.circuit[i]['derived_key'])
        if not is_endpoint:
            raise Exception("RELAY-CONNECTED CELL is modified")
        if relay_connected.relay_command != RELAY_CMD_CONNECTED:
            raise Exception("server connection failed")

        # TODO task3: Send RELAY cell with DATA command. Wait for the RELAY cell with the 
        # DATA command

        # RELAY-DATA 송신
        request = (
            "GET / HTTP/1.1\r\n"  # HTTP 요청
            f"Host: {self.web_server_ip}\r\n"  # 필수 헤더
            "Connection: close\r\n\r\n"  # 연결 닫기 명시 및 빈 라인
        ).encode('utf-8')

        relay_data = mini_cell.RELAY(self.circ_id, RELAY_CMD_DATA, 0, 0, len(request), request)
        relay_data.update_digest()

        for i in range(N):  # target까지의 모든 router, 역순으로 암호화
            relay_data = relay_data.encrypt(self.circuit[N - 1 - i]['derived_key'])
        sock.sendall(relay_data.to_bytes())

        # RELAY-DATA 수신
        circ_id, _ = self.get_header(sock)
        body = self.get_fixed_length_body(sock)
        relay_data = mini_cell.RELAY.from_bytes(body, circ_id)

        for i in range(N):  # target까지의 모든 router, 정순으로 복호화
            relay_data, is_endpoint = relay_data.decrypt(self.circuit[i]['derived_key'])
        if not is_endpoint:
            raise Exception("RELAY-DATA CELL is modified")

        http_response = relay_data.data.decode('utf-8')
        # print(http_response)

    def end_connection_to_web_server(self):
        sock = self.sock
        # TODO task4: Close the connection with the web server. Send RELAY cell with END 
        # command. Does not have to wait for any reply.
        relay_end = mini_cell.RELAY(self.circ_id, RELAY_CMD_END, 0, 0, 0, b'')
        relay_end.update_digest()

        N = len(self.circuit)
        for i in range(N):  # target까지의 모든 router, 역순으로 암호화
            relay_end = relay_end.encrypt(self.circuit[N - 1 - i]['derived_key'])
        sock.sendall(relay_end.to_bytes())
        # print("end")

    def destroy_circuit(self):
        sock = self.sock
        # TODO task4: Close the circuit. Send DESTROY cell to the first onion router. Can 
        # close the socket immediately.
        sock.sendall(mini_cell.DESTROY(self.circ_id).to_bytes())
        del self.sock
        # print("destroy")

    def directly_connect_to_web_server(self, body=None):
        sock = self.open_new_sock()
        sock.connect((self.web_server_ip, self.web_server_port))
        if body == None:
            body = 'hello from CS341!'
        header = (f'POST /echo HTTP/1.1\r\n' 
                   f'Host: {self.web_server_ip}:{self.web_server_port}\r\n'
                   f'Content-Type: text/plain\r\n'
                   f'Content-Length: {len(body)}\r\n\r\n')
        self.logger.info(f'sending payload {header+body}')
        sock.sendall((header+body).encode('utf-8'))
        response = sock.recv(4096)
        self.logger.info(f'got response from web server: {response}')
        sock.close()

    def stop(self):
        self.logger.info(f'stop() is called')
        self.running = False
        self.cleanup()

    def cleanup(self):
        self.logger.info(f'cleanup(): cleaning up client') 
        self.sock.close()
