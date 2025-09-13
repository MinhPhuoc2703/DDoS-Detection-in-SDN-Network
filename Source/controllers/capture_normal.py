from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import csv
import time
import controller
import os

# CSV file setup
CSV_FILE = './dataset/test_network_traffic.csv'
CSV_HEADERS = [
    'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst', 'ip_proto',
    'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout', 'hard_timeout',
    'flags', 'packet_count', 'byte_count', 'packet_count_per_second', 'packet_count_per_nsecond',
    'byte_count_per_second', 'byte_count_per_nsecond', 'label'
]

if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, 'a+', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        writer.writeheader()

class FlowStatsController(controller.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(FlowStatsController, self).__init__(*args, **kwargs)
        self.datapaths = {}  # Dictionary lưu thông tin các switch
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        """Gửi yêu cầu lấy thống kê từ các switch theo chu kỳ."""
        while True:
            for datapath in self.datapaths.values():
                self.send_flow_stats_request(datapath)
            hub.sleep(10)  # Chu kỳ gửi yêu cầu (10 giây)

    def send_flow_stats_request(self, datapath):
        """Gửi yêu cầu lấy thông tin thống kê luồng."""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Cập nhật danh sách datapath khi switch kết nối hoặc ngắt kết nối."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info(f"Switch {datapath.id} connected")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info(f"Switch {datapath.id} disconnected")
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        datapath_id = ev.msg.datapath.id
        timestamp = time.time()

        for stat in sorted([flow for flow in ev.msg.body if flow.priority == 1], key=lambda flow:
            (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = stat.match.get('ipv4_src', '0.0.0.0')
            tp_src = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
            ip_dst = stat.match.get('ipv4_dst', '0.0.0.0')
            tp_dst = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
            ip_proto = stat.match.get('ip_proto', 0)
            icmp_code = stat.match.get('icmpv4_code', -1)
            icmp_type = stat.match.get('icmpv4_type', -1)

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst)

            flow_data = {
                'timestamp': timestamp,
                'datapath_id': datapath_id,
                'flow_id': flow_id,
                'ip_src': ip_src,
                'tp_src': tp_src,
                'ip_dst': ip_dst,
                'tp_dst': tp_dst,
                'ip_proto': ip_proto,
                'icmp_code': icmp_code,
                'icmp_type': icmp_type,
                'flow_duration_sec': stat.duration_sec,
                'flow_duration_nsec': stat.duration_nsec,
                'idle_timeout': stat.idle_timeout,
                'hard_timeout': stat.hard_timeout,
                'flags': stat.flags,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'packet_count_per_second': self.handle_devide(stat.packet_count, stat.duration_sec),
                'packet_count_per_nsecond': self.handle_devide(stat.packet_count, stat.duration_nsec),
                'byte_count_per_second': self.handle_devide(stat.byte_count, stat.duration_sec),
                'byte_count_per_nsecond': self.handle_devide(stat.byte_count, stat.duration_nsec),
                'label': 0
            }

            # Write flow data to CSV
            with open(CSV_FILE, 'a', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
                writer.writerow(flow_data)

    @staticmethod
    def handle_devide(a, b):
        return a / b if b > 0 else 0


