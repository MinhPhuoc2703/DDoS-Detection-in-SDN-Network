from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
import controller
from datetime import datetime
import pandas as pd
import pickle

feature_columns = ['ip_src', 'ip_dst', 'tp_src', 'tp_dst', 'flow_duration_nsec', 'flags', 'packet_count', 'flow_duration_sec', 'byte_count', 'packet_count_per_second', 'byte_count_per_second']


class SimpleMonitor13(controller.SimpleSwitch13):
    
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.flow_data = {}

        # Load pre-trained model
        print("Loading pre-trained model...")
        with open("./models/dt_model.pkl", 'rb') as file:
            self.flow_model = pickle.load(file)
        print("Model loaded successfully!")

        self.host_ips = {"h1": "192.168.1.2", "h2": "192.168.1.3", "h3": "192.168.1.4", "attacker": "10.0.0.2", "server": "192.168.2.2"}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                self.logger.info(f"Switch {datapath.id} connected")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                self.logger.info(f"Switch {datapath.id} disconnected")

    def _monitor(self):
        while True:
            for datapath in self.datapaths.values():
                self.send_flow_stats_request(datapath)
            hub.sleep(10)
            self.handle_predict()

    def send_flow_stats_request(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now().timestamp()

        file = open("./dataset/network_traffic_prediction.csv","w")
        file.write(
            'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
            'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,'
            'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n'
        )

        body = ev.msg.body
        for stat in sorted([flow for flow in body if flow.priority == 1],
            key=lambda flow: (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
            tp_src, tp_dst, icmp_code, icmp_type = 0, 0, -1, -1

            if ip_proto == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']
            elif ip_proto == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']
            elif ip_proto == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = f"{ip_src}{tp_src}{ip_dst}{tp_dst}{ip_proto}"

            packet_count_per_second = self.handle_devide(stat.packet_count, stat.duration_sec)
            packet_count_per_nsecond = self.handle_devide(stat.packet_count, stat.duration_nsec)
            byte_count_per_second = self.handle_devide(stat.byte_count, stat.duration_sec)
            byte_count_per_nsecond = self.handle_devide(stat.byte_count, stat.duration_nsec)

            file.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
                        stat.match['ip_proto'],icmp_code,icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count,stat.byte_count,
                        packet_count_per_second,packet_count_per_nsecond,
                        byte_count_per_second,byte_count_per_nsecond))
        file.close()

    @staticmethod
    def handle_devide(a, b):
        return a / b if b > 0 else 0

    def preprocessing(self, dataset):
        dataset = dataset[feature_columns]
        dataset.loc[:, 'ip_src'] = dataset['ip_src'].str.replace('.', '')
        dataset.loc[:, 'ip_dst'] = dataset['ip_dst'].str.replace('.', '')
        return dataset


    def handle_predict(self):
        try:
            dataset = pd.read_csv('./dataset/network_traffic_prediction.csv')
            predict_flow_dataset = self.preprocessing(dataset)

            # Chuyển đổi dữ liệu sang định dạng numpy
            X_predict_flow = predict_flow_dataset.values.astype(float)

            # Sử dụng mô hình đã huấn luyện để dự đoán
            y_flow_pred = self.flow_model.predict(X_predict_flow)
            self.handle_ddos_mitigation(y_flow_pred, predict_flow_dataset)
            self.reset_prediction()
        except:
            pass

    def handle_ddos_mitigation(self, y_pred, dataset):
        self.logger.info("------------------------------------------------------------------------------")
        legitimate_trafic = sum(1 for i in y_pred if i == 0)
        ddos_trafic = len(y_pred) - legitimate_trafic

        if (legitimate_trafic / (legitimate_trafic + ddos_trafic) * 100) > 80:
            self.logger.info("Benign traffic ...")
        else:
            if ddos_trafic > 1 and dataset.iloc[ddos_trafic - 2]['ip_dst'] == dataset.iloc[ddos_trafic - 1]['ip_dst']:
                victim_ip = dataset.iloc[ddos_trafic - 1]['ip_dst']
                for host, ip in self.host_ips.items():
                    format_host_ip = ip.replace(".", "")
                    if (victim_ip == format_host_ip):
                        self.logger.warning("DDoS attack is detected!!!")
                        self.logger.warning(f"Victim is host: {host}")
        self.logger.info("------------------------------------------------------------------------------")

    @staticmethod
    def reset_prediction():
        file = open("./dataset/network_traffic_prediction.csv","w")
        file.write(
            'timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,'
            'flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,'
            'packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond\n'
        )
        file.close()
