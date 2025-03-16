import pyshark
import csv
import os

file_path = os.path.abspath(__file__)
path = os.path.dirname(file_path)
measurement_dir = os.path.join(path, '../measurement/')
os.makedirs(measurement_dir, exist_ok=True)

# 패킷 정보 불러오기
cap_path = 'C:/Users/MASTER/OneDrive/문서/chunks.pcapng'
cap = pyshark.FileCapture(cap_path, display_filter='quic or http3')

chunk_data = []
initial_timestamp = None

# 패킷 분석
for packet in cap:
    try:
        # payload 지닌 quic 패킷 분석
        if 'QUIC' in packet and hasattr(packet.quic, 'protected_payload'):
            print('quic')
            # chunk size 계산
            chunk_size = len(packet.quic.protected_payload.raw_value)
            timestamp = float(packet.sniff_time.timestamp())

            if initial_timestamp is None:  # Capture the first timestamp
                initial_timestamp = timestamp

            # Make timestamp relative to the first packet and convert to minutes
            relative_time = (timestamp - initial_timestamp)
            chunk_data.append((relative_time, chunk_size))
            print(relative_time, chunk_size)

        # http3 패킷 분석
        elif 'HTTP3' in packet and hasattr(packet.http3, 'data'):
            print('http3')
            # chunk size 계산
            chunk_size = len(packet.http3.data.raw_value)
            timestamp = float(packet.sniff_time.timestamp())

            if initial_timestamp is None:  # Capture the first timestamp
                initial_timestamp = timestamp

            # Make timestamp relative to the first packet and convert to minutes
            relative_time = (timestamp - initial_timestamp) / 60.0
            chunk_data.append((relative_time, chunk_size))
            print(chunk_size)

    except AttributeError:
        continue

# CSV file saving
with open(measurement_dir + '/youtube_burst_measurements_0.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Timestamp (minutes)', 'Chunk Size'])  # Create header
    writer.writerows(chunk_data)  # Save data
