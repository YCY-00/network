#!/usr/bin/python3

from scapy import *
import pox.openflow.libopenflow_01 as of

# KAIST CS341 SDN Lab Task 2, 3, 4
#
# All functions in this file runs on the controller:
#   - init(net):
#       - runs only once for network, when initialized
#       - the controller should process the given network structure for future behavior
#   - addrule(switchname, connection):
#       - runs when a switch connects to the controller
#       - the controller should insert routing rules to the switch
#   - handlePacket(packet, connection):
#       - runs when a switch sends unhandled packet to the controller
#       - the controller should decide whether to handle the packet:
#           - let the switch route the packet
#           - drop the packet
#
# Task 2: Getting familiarized with POX 
#   - Let switches "flood" packets
#   - This is not graded
# 
# Task 3: Implementing a Simple Routing Protocol
#   - Let switches route via Dijkstra
#   - Match ARP and ICMP over IPv4 packets
#
# Task 4: Redirecting all DNS request packets to controller 
#   - Let switches send all DNS packets to Controller
#       - Create proper forwarding rules, send all DNS queries and responses to the controller
#       - HTTP traffic should not be forwarded to the controller
#       
# Task 5: Implementing a Simple DNS-based Censorship
#   - Check DNS request
#       - If request contains task5-block.com, return empty DNS response instead of routing it
#       
# Task 6: Implementing more efficient DNS-based censorship 
#   - Let switches send only DNS query packets to Controller
#       - Create proper forwarding rules, send only DNS queries to the controller
#   - Check if DNS query contains cs341dangerous.com
#       - If such query is found, insert a new rule to switch to track the DNS response
#           - let the swtich route DNS response to the controller
#       - When the corresponding DNS response arrived, do followings:
#           - parse DNS response, insert a new rule to block all traffic from/to the server
#           - reply the DNS request with empty DNS response
#       - For all other packets, route them normally
#
# Task 7: Extending Censorship to Normal Network
#   - At any time, HTTP and DNS server can be changed by following:
#     - Create new server, hosting either task7-block-<one or more digits>.com or task7-open-<one or more digits>.com
#       - DNS server adds new record, HTTP server adds new domain
#     - For certain domain, hosting server changes
#       - DNS server changes record, HTTP server is replaced to another one
#     - For certain domain, hosting stops
#       - DNS server removes record, HTTP server removes the domain
#  - For 3 changes above, HTTP servers and DNS servers are changed instantly
#  - Assume that
#    - single IP might host multiple domains
#    - the IP should be blocked if it hosts at least one task7-block-<one or more digits>.com
#    - Only one IP is assigned to one domain
#    - If you detect different DNS response for same DNS request, assume that previous IP does not host the domain anymore


###
# If you want, you can define global variables, import Python built-in libraries, or do others
import heapq  # for dijkstra
from pox.lib.addresses import IPAddr  # string to ip address
###

def init(self, net) -> None:
    #
    # net argument has following structure:
    # 
    # net = {
    #    'hosts': {
    #         'h1': {
    #             'name': 'h1',
    #             'IP': '10.0.0.1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('h1', 1, 's1', 2, 3)
    #             ],
    #         },
    #         ...
    #     },
    #     'switches': {
    #         's1': {
    #             'name': 's1',
    #             'links': [
    #                 # (node1, port1, node2, port2, link cost)
    #                 ('s1', 2, 'h1', 1, 3)
    #             ]
    #         },
    #         ...
    #     }
    # }
    #
    pass
    ###
    # YOUR CODE HERE
    # Task 2-네트워크 초기화
    self.network = net
    self.connections = []
    self.domain_dict = {}  # domian-ip map

    # Task 3-network 그래프 생성(parsing)
    self.graph = {}
    for switchname, data in self.network['switches'].items():
        if switchname not in self.graph:
            self.graph[switchname] = {}

        for link in data['links']:
            node1, port1, node2, port2, cost = link
            if node2 not in self.graph:
                self.graph[node2] = {}

            # 양방향 연결 추가(cost, output port)
            self.graph[node1][node2] = (cost, port1)
            self.graph[node2][node1] = (cost, port2)

    # Task 3-Dijkstra
    self.routes = {}
    for switchname in self.graph:
        # 변수 초기화
        distances = {node: float('inf') for node in self.graph}
        previous_nodes = {node: None for node in self.graph}
        host_nodes = {self.network['hosts'][node]['IP']: node for node in self.graph if node in self.network['hosts'].keys()}
        visited_queue = [(0, switchname)]
        distances[switchname] = 0
        previous_nodes

        while visited_queue:
            current_distance, current_node = heapq.heappop(visited_queue)
            for neighbor, (cost, port) in self.graph[current_node].items():
                distance = current_distance + cost
                # 거리가 짧아진 경우 update
                if distance < distances[neighbor]:
                    heapq.heappush(visited_queue, (distance, neighbor))
                    distances[neighbor] = distance

                    # node가 이미 존재하는 경우, 이전 port 재사용(전달할 output 포트는 동일)
                    if previous_nodes[current_node] is not None:
                        _, port = previous_nodes[current_node]

                    previous_nodes[neighbor] = (current_node, port)

        # dst_ip-port map 생성
        for ip, node in host_nodes.items():
            if previous_nodes[node] is not None:
                _, port = previous_nodes[node]
                host_nodes[ip] = port

        self.routes[switchname] = host_nodes
    ###

def addrule(self, switchname: str, connection) -> None:
    #
    # This function is invoked when a new switch is connected to controller
    # Install table entry to the switch's routing table
    #
    # For more information about POX openflow API,
    # Refer to [POX official document](https://noxrepo.github.io/pox-doc/html/),
    # Especially [ofp_flow_mod - Flow table modification](https://noxrepo.github.io/pox-doc/html/#ofp-flow-mod-flow-table-modification)
    # and [Match Structure](https://noxrepo.github.io/pox-doc/html/#match-structure)
    #
    # your code will be look like:
    # msg = ....
    # connection.send(msg)
    pass
    ###
    # YOUR CODE HERE
    if connection not in self.connections:
        self.connections.append(connection)

    '''
    # Task 2-기본 라우팅 규칙(flood)
    msg = of.ofp_flow_mod()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))  # of.OFPP_FLOOD: 입력 port를 제외한 모든 활성 port(가능한 모든 출력 port)
    connection.send(msg)
    '''

    # Task 3-forwarding table 생성
    for host_ip, port in self.routes[switchname].items():
        # ARP: ip-MAC 매핑
        arp_msg = of.ofp_flow_mod()
        arp_msg.priority = 10
        arp_msg.match.dl_type = 0x806  # ARP
        arp_msg.match.nw_dst = IPAddr(host_ip)
        arp_msg.actions.append(of.ofp_action_output(port=port))
        connection.send(arp_msg)

        # ICMP: ping
        icmp_msg = of.ofp_flow_mod()
        icmp_msg.priority = 10
        icmp_msg.match.dl_type = 0x800  # IPv4
        icmp_msg.match.nw_dst = IPAddr(host_ip)
        icmp_msg.actions.append(of.ofp_action_output(port=port))
        connection.send(icmp_msg)

    # Task 4: DNS query 전달
    dns_msg = of.ofp_flow_mod()
    dns_msg.priority = 20
    dns_msg.match.dl_type = 0x800  # IPv4
    dns_msg.match.nw_proto = 17   # UDP
    dns_msg.match.tp_dst = 53     # Port 53 for DNS
    dns_msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
    connection.send(dns_msg)
    ###

from scapy.all import * # you can use scapy in this task

def handlePacket(self, switchname, event, connection):
    packet = event.parsed
    if not packet.parsed:
        print('Ignoring incomplete packet')
        return
    # Retrieve how packet is parsed
    # Packet consists of:
    #  - various protocol headers
    #  - one content
    # For example, a DNS over UDP packet consists of following:
    # [Ethernet Header][           Ethernet Body            ]
    #                  [IPv4 Header][       IPv4 Body       ]
    #                               [UDP Header][ UDP Body  ]
    #                                           [DNS Content]
    # POX will parse the packet as following:
    #   ethernet --> ipv4 --> udp --> dns
    # If POX does not know how to parse content, the content will remain as `bytes`
    #     Currently, HTTP messages are not parsed, remaining `bytes`. you should parse it manually.
    # You can find all available packet header and content types from pox/pox/lib/packet/
    packetfrags = {}
    p = packet
    while p is not None:
        packetfrags[p.__class__.__name__] = p
        if isinstance(p, bytes):
            break
        p = p.next
    print(packet.dump()) # print out received packet
    # How to know protocol header types? see name of class

    # If you want to send packet back to switch, you can use of.ofp_packet_out() message.
    # Refer to [ofp_packet_out - Sending packets from the switch](https://noxrepo.github.io/pox-doc/html/#ofp-packet-out-sending-packets-from-the-switch)
    # You may learn from [l2_learning.py](pox/pox/forwarding/l2_learning.py), which implements learning switches
    
    # You can access other switches via self.controller.switches
    # For example, self.controller.switches[0].connection.send(msg)

    ###
    # YOUR CODE HERE
    # Task 4-DNS query 처리
    ipv4 = packetfrags.get("ipv4")
    udp = packetfrags.get("udp")
    ether = packetfrags.get("ethernet")

    # port 결정
    if ipv4:
        dst_port = self.controller.routes[switchname][str(ipv4.dstip)]

    if ipv4 and udp and udp.dstport == 53:
        print("Received DNS packet")

        # Task 5-DNS 검열
        dns = packetfrags.get("dns")
        domain_name = dns.questions[0].name
        if domain_name == 'task5-block.com':
            print("DNS is blocked")
            # empty DNS RESPONSE 생성(qr=1(response), rcode=3(no domain), rd=0(recursive X))
            scapy_packet = Ether(dst=ether.src, src=ether.dst)/IP(src=ipv4.dstip, dst=ipv4.srcip)/UDP(dport=udp.srcport, sport=53)/DNS(id=dns.id, qr=1, rd=0, rcode=3, qd=DNSQR(qname=domain_name))

            # 전송
            msg = of.ofp_packet_out()
            msg.data = bytes(scapy_packet)
            msg.actions.append(of.ofp_action_output(port=event.port))  # 원래 port로 전송
            connection.send(msg)
            return  # 작업 종료

        # Task 6-검열된 DNS 응답 controller 연결
        elif domain_name == 'task6-block.com' or 'task7-block' in domain_name:
            print("add new rules")
            new_msg = of.ofp_flow_mod()
            new_msg.priority = 20
            new_msg.match.dl_type = 0x0800  # IPv4
            new_msg.match.nw_proto = 17  # UDP
            new_msg.match.tp_src = 53  # DNS "응답" port
            new_msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            for connect in self.controller.connections:
                connect.send(new_msg)

        # 보내야 하는 포트 탐색
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=dst_port))
        connection.send(msg)

    # Task 6-DNS 응답을 받아 IP 차단
    if ipv4 and udp and udp.srcport == 53:
        print("Blocked DNS")

        # rule 삭제
        print("delete rules")
        delete_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        delete_msg.priority = 20
        delete_msg.match.dl_type = 0x0800  # IPv4
        delete_msg.match.nw_proto = 17  # UDP
        delete_msg.match.tp_src = 53  # DNS "응답" port
        delete_msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        for connect in self.controller.connections:
            connect.send(delete_msg)

        # ip 차단 정책 추가
        dns = packetfrags.get("dns")
        domain_name = dns.questions[0].name
        blocked_ip = dns.answers[0].rddata

        # Task 7-domain & ip 관계 확인
        if domain_name not in self.controller.domain_dict.keys():
            self.controller.domain_dict[domain_name] = blocked_ip
        # ip 변경
        elif self.controller.domain_dict[domain_name] != blocked_ip:
            print("delete ip rules")
            # 이전 정책 삭제
            msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
            msg.priority = 30
            msg.match.dl_type = 0x0800  # IPv4
            msg.match.nw_proto = 6  # TCP
            msg.match.tp_dst = 80  # HTTP
            msg.match.nw_dst = IPAddr(self.controller.domain_dict[domain_name])  # 이전 ip
            for connect in self.controller.connections:
                connect.send(msg)

            # domain_dict 업데이트
            self.controller.domain_dict[domain_name] = blocked_ip

        ip_msg = of.ofp_flow_mod()
        ip_msg.priority = 30
        ip_msg.match.dl_type = 0x0800  # IPv4
        ip_msg.match.nw_proto = 6  # TCP
        ip_msg.match.tp_dst = 80  # HTTP
        ip_msg.match.nw_dst = IPAddr(blocked_ip)
        # msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))  # drop
        for connect in self.controller.connections:
            connect.send(ip_msg)

        # empty DNS RESPONSE 생성(qr=1(response), rcode=3(no domain), rd=0(recursive X))
        print("empty response")
        scapy_packet = Ether(dst=ether.dst, src=ether.src)/IP(src=ipv4.srcip, dst=ipv4.dstip)/UDP(dport=udp.dstport, sport=53)/DNS(id=dns.id, qr=1, rd=0, rcode=3, qd=DNSQR(qname=domain_name))

        # 전송
        empty_msg = of.ofp_packet_out()
        empty_msg.data = bytes(scapy_packet)
        empty_msg.actions.append(of.ofp_action_output(port=dst_port))
        connection.send(empty_msg)
    ###
