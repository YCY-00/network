import pyshark
import sys


def analyze_speaking(pcap_file, threshold):
    # sr packet 탐색: 마이크만 사용하므로, audio streaming만 고려
    cap = pyshark.FileCapture(pcap_file,
                              display_filter='udp and udp.port == 8801 and udp.payload[0] == 05 and udp.payload contains 01:00 and udp.payload contains 22 and udp.payload contains 80:c8')

    active_speaking = {}
    prev_packet_count = {}

    # 패킷 분석
    for packet in cap:
        try:
            payload_list = packet.udp.payload.split(':')
            for i in range(len(payload_list)-1):
                # sr_id 및 packet_count 계산
                if payload_list[i] == '80' and payload_list[i+1] == 'c8':
                    # sr_id 위치가 맞는지 조건 확인
                    if i > 15 and payload_list[i-16] == '22' and payload_list[i+4] == '01' and payload_list[i+5] == '00' and payload_list[i+7] == '02':
                        # media type 2 btye 이후에 id
                        sr_id = ''.join(payload_list[i+4:i+7])
                        # sr_id 12 byte 이후에 packet_count
                        packet_count = int('0x'+''.join(payload_list[i+20:i+24]), 16)

                        # sr_id가 처음 발생한 경우 active_speaking에 연관 list 추가
                        if sr_id not in prev_packet_count.keys():
                            active_speaking[sr_id] = []
                        # threshold보다 차이가 크면 active_speaking에 시간 추가
                        elif packet_count - prev_packet_count[sr_id] > threshold:
                            active_speaking[sr_id].append(str(packet.sniff_time))

                        # prev_packet_count 업데이트
                        prev_packet_count[sr_id] = packet_count

                        break

        except AttributeError:
            continue

    # rs_id 인식에 문제가 발생한 경우
    if len(active_speaking.keys()) != 2:
        print("error")
        return None

    # txt 생성용 표준 출력
    for i, key in enumerate(active_speaking.keys()):
        # rs_id 출력
        if i == 0:
            print(f"Alice {key}")
        elif i == 1:
            print(f"\nBob {key}")

        # timestamp 출력
        for value in active_speaking[key]:
            print(value)


if __name__ == '__main__':
    # arg 부족
    if len(sys.argv) != 3:
        print("python speaker-analysis.py <pcap_file> <threshold>")

    pcap_file = sys.argv[1]
    threshold = int(sys.argv[2])

    analyze_speaking(pcap_file, threshold)
