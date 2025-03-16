import struct
from zlib import crc32
import mini_crypt

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

CELL_FIXED_BODY_LEN = 1024
RSA2048_SIGN_LEN = 256
DH_G = 2
DH_P = int("BC6E230F63512CB36605599417DE96B6DE189B93E63250EFAF457462533D8EBB"
           "EF362F478BDBDAEB4E0726F4102F54F6B58CB70C5257A829456D981A2E5FCD7B",
           16)
DH_PUB_NUM_LEN = 128


class VERSIONS:
    def __init__(self, versions_list):
        self.circ_id = 0
        self.command = CELL_CMD_VERSIONS
        self.versions_list = versions_list

    def from_bytes(cell_body:bytes, cell_body_len:int):
        if cell_body_len % 2 != 0: 
            raise Exception(f'VERSIONS cell length(={cell_body_len}) is not multiples of 2')
        versions_list = []
        for i in range(0, cell_body_len, 2):
            versions_list.append(int.from_bytes(cell_body[i:i+2], byteorder='big'))
        return VERSIONS(versions_list)

    def to_bytes(self) -> bytes:
        cell_body = b''
        for version in self.versions_list:
            cell_body += (version).to_bytes(2, byteorder='big')
        cell_len = len(cell_body)
        header = struct.pack('!HBH', self.circ_id, self.command, cell_len)
        return header + cell_body

class CERTS: 
    def __init__(self, pem, signature):
        self.circ_id = 0
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # CERTS: 번호 X, 길이 고정, 인증서 제공
        # format: PEM, signature
        self.command = CELL_CMD_CERTS
        self.PEM = pem
        self.signature = signature

    def from_bytes(cell_body:bytes):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # byte to object
        start_idx = 0
        end_idx = start_idx + 380
        pem = cell_body[start_idx:end_idx]
        start_idx = end_idx
        end_idx += RSA2048_SIGN_LEN
        signature = cell_body[start_idx:end_idx]
        return CERTS(pem, signature)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        header = struct.pack('!HB', self.circ_id, self.command)  # 객체를 bytes로 전환(!HB: id(2)+command(1))
        cell_body = b''
        cell_body += self.PEM
        cell_body += self.signature
        padding = b'\x00' * (CELL_FIXED_BODY_LEN - len(cell_body))
        return header + cell_body + padding

class NETINFO:
    def __init__(self, peer_addr_len, peer_addr, my_addr_len, my_addr):
        self.circ_id = 0
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # NETINFO: 번호 X, 길이 가변, 네트워크 정보(IP) 교환으로 연결 상태 확인
        # format: peer_addr_len(1), peer_addr(peer_addr_len), my_addr_len(1), my_addr(my_addr_len)
        self.command = CELL_CMD_NETINFO
        self.peer_addr_len = peer_addr_len
        self.peer_addr = peer_addr
        self.my_addr_len = my_addr_len
        self.my_addr = my_addr

    def from_bytes(cell_body:bytes):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        start_idx = 0
        end_idx = start_idx + 1
        peer_addr_len = int.from_bytes(cell_body[start_idx:end_idx], byteorder='big')
        start_idx = end_idx
        end_idx += peer_addr_len
        peer_addr = cell_body[start_idx:end_idx]
        start_idx = end_idx
        end_idx += 1
        my_addr_len = int.from_bytes(cell_body[start_idx:end_idx], byteorder='big')
        start_idx = end_idx
        end_idx += my_addr_len
        my_addr = cell_body[start_idx:end_idx]
        return NETINFO(peer_addr_len, peer_addr, my_addr_len, my_addr)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        cell_body = b''
        cell_body += self.peer_addr_len.to_bytes(1, byteorder='big')
        cell_body += self.peer_addr
        cell_body += self.my_addr_len.to_bytes(1, byteorder='big')
        cell_body += self.my_addr
        cell_length = len(cell_body)
        header = struct.pack('!HBH', self.circ_id, self.command, cell_length)  # 객체를 bytes로 전환(HBH: id(2)+command(1)+length(2))
        return header + cell_body

class CREATE:
    def __init__(self, circ_id, encrypted_dh_pubk):
        self.circ_id = circ_id
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # CREATE: 번호 존재, 길이 가변, 회로 생성
        # format: public_key(256)
        self.command = CELL_CMD_CREATE
        self.encryted_DH_public_key = encrypted_dh_pubk

    def from_bytes(cell_body:bytes, circ_id:int):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        encypted_public_key = cell_body
        return CREATE(circ_id, encypted_public_key)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        cell_body = b''
        cell_body += self.encryted_DH_public_key  # 암호화된 공개 키의 길이는 256으로 고정
        cell_length = len(cell_body)
        header = struct.pack('!HBH', self.circ_id, self.command, cell_length)  # 객체를 bytes로 전환(HBH: id(2)+command(1)+length(2))
        return header + cell_body        

class CREATED:
    def __init__(self, circ_id, public_key, signature):
        self.circ_id = circ_id
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # 번호 존재, 길이 가변, 회로 생성에 대한 ACK
        # format: public_key(128), signature(256)
        self.command = CELL_CMD_CREATED
        self.DH_public_key = public_key
        self.signature = signature

    def from_bytes(cell_body:bytes, circ_id:int):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        start_idx = 0
        end_idx = start_idx + DH_PUB_NUM_LEN
        public_key = cell_body[start_idx:end_idx]
        start_idx = end_idx
        end_idx += RSA2048_SIGN_LEN
        signature = cell_body[start_idx:end_idx]
        return CREATED(circ_id, public_key, signature)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        cell_body = b''
        cell_body += self.DH_public_key
        cell_body += self.signature
        cell_length = len(cell_body)
        header = struct.pack('!HBH', self.circ_id, self.command, cell_length)  # 객체를 bytes로 전환(HBH: id(2)+command(1)+length(2))
        return header + cell_body

class RELAY:
    def __init__(self, circ_id, relay_cmd, recognized, digest, data_length, data):
        self.circ_id = circ_id
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # 번호 존재, 길이 고정, data 중계
        # format: relay command(1), recognized(2), digest(4), data_length(2), data(data_length), padding
        self.command = CELL_CMD_RELAY
        self.relay_command = relay_cmd  # RELAY_CMD_
        self.recognized = recognized  # 암호화 여부 표시(암호화 X 시 0 -> 암호화 시 암호화된 무작위 바이트로 body가 변하면서 0이 아닌 값으로 변경 -> 우연히 0이 될 확률 존재)
        self.digest = digest # 복호화 검증을 통해 진짜 복호화가 전부 완료되었는지 확인
        self.data_length = data_length
        self.data = data

    def from_bytes(cell_body:bytes, circ_id):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        start_idx = 0
        end_idx = start_idx + 1
        relay_command = int.from_bytes(cell_body[start_idx:end_idx], byteorder='big')
        start_idx = end_idx
        end_idx += 2
        recognized = int.from_bytes(cell_body[start_idx:end_idx], byteorder='big')
        start_idx = end_idx
        end_idx += 4
        digest = int.from_bytes(cell_body[start_idx:end_idx], byteorder='big')
        start_idx = end_idx
        end_idx += 2
        data_length = int.from_bytes(cell_body[start_idx:end_idx], byteorder='big')
        start_idx = end_idx
        data = cell_body[start_idx:]  # data_length를 사용하는 경우, 암호화로 인해 data_length가 변조된 경우 오류가 발생할 수 있으므로 나머지로 설정(CRT 모드로 인해 암호화 후에도 길이 동일)
        return RELAY(circ_id, relay_command, recognized, digest, data_length, data)

    def to_bytes(self) -> bytes:
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        header = struct.pack('!HB', self.circ_id, self.command)  # 객체를 bytes로 전환(!HB: id(2)+command(1))
        cell_body = b''
        cell_body += self.relay_command.to_bytes(1, byteorder='big')
        cell_body += self.recognized.to_bytes(2, byteorder='big')
        cell_body += self.digest.to_bytes(4, byteorder='big')
        cell_body += self.data_length.to_bytes(2, byteorder='big')
        cell_body += self.data
        padding = b''.ljust(CELL_FIXED_BODY_LEN - len(cell_body), b'\x00')
        return header + cell_body + padding

    # use crc32() checksum to calculate the digest. 
    # e.g., self.digest = crc32(self.body)
    def update_digest(self):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # digest field 설명에 주어진 flow에 따라 작성, client에서의 최초 전송 시에만 계산되어 매 or에서 자신의 계산 값과 비교
        relay_cmd = struct.pack('!B', self.relay_command)
        recognized = struct.pack('!H', 0)  # 2 byte, client에서만 digest setting이 이루어지므로, 항상 0
        empty_digest = struct.pack('!I', 0)  # 4 byte
        data_length_field = struct.pack('!H', self.data_length)  # 2 byte
        padding = b''.ljust(CELL_FIXED_BODY_LEN - 9 - len(self.data), b'\x00')
        tmp = relay_cmd + recognized + empty_digest + data_length_field + self.data + padding
        self.digest = crc32(tmp)
        # print("origin tmp:", tmp[:10], self.digest)

    # Should first update the digest, then encrypt the cell with shared secret key
    def encrypt(self, sym_key):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # 암호화는 endpoint에서 M회 반복 실행 -> sym_key_list를 받아서 반복 처리?
        cell_body = self.to_bytes()[3:]
        encrypted = mini_crypt.AES_encrypt(sym_key, cell_body)  # 공개 키를 사용하여 암호화
        return RELAY.from_bytes(encrypted, self.circ_id)  # CRT 모드를 사용하여 입력 크기와 출력 크기가 같으므로, relay 객체처럼 처리 가능

    # Should first decrypt the cell with shared secret key, then check the digest
    def decrypt(self, sym_key):
        # TODO: Your code here. You may add, remove, and change the arguments for the method
        # 복호화는 layer마다 1번씩 실행
        cell_body = self.to_bytes()[3:]
        decrypted = mini_crypt.AES_decrypt(sym_key, cell_body)  # 공개 키를 사용하여 복호화

        # recognized가 0인 경우, digest 비교를 통해 복호화 여부 확인
        recognized = struct.unpack('!H', decrypted[1:3])[0]
        if recognized == 0:
            empty_digest = struct.pack('!I', 0)  # 4 byte
            tmp = decrypted[:3] + empty_digest + decrypted[7:]  # 원본과 같이 digest를 empty로 설정
            digest = crc32(tmp)
            # print("new tmp:", tmp[:10], digest)  # 2회 이상 암호화 시 원본과 달라짐 -> data_length를 len(data)로 설정해 벌어진 문제였다!

            # 원래 digest와 동일한지 확인
            if digest == struct.unpack('!I', decrypted[3:7])[0]:  # unpack: byte to int, 항상 tuple 반환
                # 정보 update 후 반환
                return RELAY.from_bytes(decrypted, self.circ_id), True  # 완전 복호화

        return RELAY.from_bytes(decrypted, self.circ_id), False

### relay body ###
class RELAY_EXTEND:
    def __init__(self, or_name_len, or_name, encypted_dh_pubk):
        self.or_name_len = or_name_len
        self.or_name = or_name
        self.encrypted_DH_public_key = encypted_dh_pubk

    def from_bytes(data:bytes):
        or_name_len = data[0]
        start_idx = 1
        end_idx = start_idx + or_name_len
        or_name = data[start_idx:end_idx]
        start_idx = end_idx
        end_idx += 256
        encypted_dh_pubk = data[start_idx:end_idx]
        return RELAY_EXTEND(or_name_len, or_name, encypted_dh_pubk)

    def to_bytes(self) -> bytes:
        data = b''
        data += self.or_name_len.to_bytes(1, byteorder='big')
        data += self.or_name
        data += self.encrypted_DH_public_key
        return data

class RELAY_EXTENDED:
    def __init__(self, dh_pubk, signature):
        self.DH_public_key = dh_pubk
        self.signature = signature

    def from_bytes(data:bytes):
        start_idx = 0
        end_idx = start_idx + DH_PUB_NUM_LEN
        dh_pubk = data[start_idx:end_idx]
        start_idx = end_idx
        end_idx += RSA2048_SIGN_LEN
        signature = data[start_idx:end_idx]
        return RELAY_EXTENDED(dh_pubk, signature)

    def to_bytes(self) -> bytes:
        data = b''
        data += self.DH_public_key
        data += self.signature
        return data

class RELAY_BEGIN: 
    def __init__(self, target_addr_len, target_addr):
        self.target_addr_len = target_addr_len
        self.target_addr = target_addr

    def from_bytes(data:bytes):
        target_addr_len = data[0]
        start_idx = 1
        end_idx = start_idx + target_addr_len
        target_addr = data[start_idx:end_idx]
        return RELAY_BEGIN(target_addr_len, target_addr)

    def to_bytes(self) -> bytes:
        data = b''
        data += self.target_addr_len.to_bytes(1, byteorder='big')
        data += self.target_addr
        return data

'''
class RELAY_CONNECTED:
    def __init__(self, target_addr_len, target_addr):
        self.target_addr_len = target_addr_len
        self.target_addr = target_addr

    def from_bytes(data:bytes):
        target_addr_len = int.from_bytes(data[0], byteorder='big')
        start_idx = 1
        end_idx = start_idx + target_addr_len
        target_addr = data[start_idx:end_idx]
        return RELAY_EXTEND(target_addr_len, target_addr)

    def to_bytes(self) -> bytes:
        data = b''
        data += self.target_addr_len.to_bytes(1, byteorder='big')
        data += self.target_addr
        return data

class RELAY_DATA:
    def __init__(self, data):
        self.data = data

    def from_bytes(data:bytes):
        return RELAY_DATA(data)

    def to_bytes(self) -> bytes:
        return self.data
'''
### relay body ###

class DESTROY:
    def __init__(self, circ_id):
        self.circ_id = circ_id
        self.command = CELL_CMD_DESTROY
        self.data = b''.ljust(CELL_FIXED_BODY_LEN, b'\x00')

    def to_bytes(self) -> bytes:
        header = struct.pack('!HB', self.circ_id, self.command)
        return header + self.data

if __name__ == '__main__':
    print('You may test your codes here. This method will not be graded.')
    print('You may also add other classes and new methods for the existing classes.')
