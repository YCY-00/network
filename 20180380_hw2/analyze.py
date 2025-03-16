import matplotlib.pyplot as plt
from scapy.all import rdpcap, TCP

# scapy 사용
with open('./dump.pcap', 'rb') as pcap_file:
    packets = rdpcap(pcap_file)

# x, y list 초기화
times = []
segments_sent = []
throughputs = []

# 변수 초기화
initial_time = None
last_time = 0
seg_count = 0
MMS = 65469

for packet in packets:
    if TCP in packet:
        # client -> server(data transmit)
        if packet[TCP].sport == 45448:
            # segment 길이가 MMS 이하인 packet 무시
            if len(packet[TCP].payload) != MMS:
                continue

            # 시작 시간 설정
            if initial_time is None:
                initial_time = packet.time

            current_time = packet.time - initial_time
            seg_count += 1

            times.append(current_time)
            segments_sent.append(seg_count)

            # 초반 분모 0
            if current_time == 0:
                throughputs.append(0)
                continue
            throughputs.append(MMS*8/(current_time-last_time))
            last_time = current_time

plt.figure(figsize=(10, 5))

# segment plot 작성
plt.subplot(2, 1, 1)
plt.plot(times, segments_sent, label='Segment Sent', color='blue')

plt.xlabel('Time (seconds)')
plt.ylabel('Segments')
plt.title('TCP Congestion Control Behavior-Number of Segments')
plt.legend()

# wnd plot 작성
plt.subplot(2, 1, 2)
plt.plot(times, throughputs, label='Throughput', color='red')

plt.xlabel('Time (seconds)')
plt.ylabel('Throughput (bps)')
plt.title('TCP Congestion Control Behavior-Troughput')
plt.legend()

# plot 저장
plt.tight_layout()
plt.savefig('./plot.png')
