"""
Final Project Code: An advanced SDN application for real-time DDoS detection 
with a two-stage hybrid algorithm and a WebSocket API for frontend integration.
"""
# Import necessary Ryu and standard libraries
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub

import time
import joblib
import numpy as np
import os
import warnings
from sklearn.exceptions import InconsistentVersionWarning

# --- API & WEB SERVER IMPORTS ---
from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS
import threading
from threading import Lock
import eventlet
# --------------------------------

# Suppress scikit-learn warnings for a cleaner log
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')
warnings.filterwarnings("ignore", category=InconsistentVersionWarning, module='sklearn')

# --- FLASK & SOCKET.IO GLOBAL SETUP ---
flask_app = Flask(__name__)
CORS(flask_app)
socketio = SocketIO(flask_app, cors_allowed_origins="*", async_mode='eventlet')
eventlet.monkey_patch()
# ------------------------------------

class RealtimeDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RealtimeDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_table = {}
        self.victim_tracker = {}
        self.active_mitigations = {}
        self.api_lock = Lock()
        self.logger.info("SDN DDoS Detector Application Started.")
        
        # Load the ML Model
        model_path = 'models/syn_flood_model.joblib'
        self.model = joblib.load(model_path) if os.path.exists(model_path) else None
        if self.model: self.logger.info("ML Model loaded successfully from %s", model_path)
        else: self.logger.warning("ML model not found at %s. Running in monitoring mode only.", model_path)
        
        self.flask_thread = threading.Thread(target=self._run_flask_app)
        self.flask_thread.daemon = True
        self.flask_thread.start()
        
        self.monitor_thread = hub.spawn(self._monitor)

    def _run_flask_app(self):
        @flask_app.route('/api/flows', methods=['GET'])
        def get_active_flows():
            with self.api_lock:
                flow_list = []
                for flow_key, flow_stats in self.flow_table.items():
                    flow_obj = {
                        "sourceIp": flow_key[0], "destinationIp": flow_key[1], "protocol": flow_key[2],
                        "sourcePort": flow_key[3] if len(flow_key) > 3 else 'N/A',
                        "destinationPort": flow_key[4] if len(flow_key) > 4 else 'N/A',
                        "status": flow_stats.get('status', 'active'),
                        "packetCount": flow_stats.get('fwd_packet_count', 0)
                    }
                    flow_list.append(flow_obj)
                
                page = request.args.get('page', 1, type=int)
                limit = request.args.get('limit', 50, type=int)
                start = (page - 1) * limit
                end = start + limit
                paginated_flows = flow_list[start:end]
                
                return jsonify({
                    'totalPages': (len(flow_list) + limit - 1) // limit,
                    'currentPage': page, 'flows': paginated_flows
                })

        @flask_app.route('/api/mitigations', methods=['GET'])
        def get_active_mitigations():
            with self.api_lock:
                return jsonify(list(self.active_mitigations.values()))
        
        self.logger.info("Starting Flask API server on http://0.0.0.0:5000")
        socketio.run(flask_app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Default flow rule installed on switch %s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod_args = {'datapath': datapath, 'priority': priority, 'match': match,
                    'instructions': inst, 'idle_timeout': idle_timeout, 'hard_timeout': hard_timeout}
        if buffer_id: mod_args['buffer_id'] = buffer_id
        mod = parser.OFPFlowMod(**mod_args)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port
        out_port = self.mac_to_port[datapath.id].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        with self.api_lock:
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip:
                self._update_flow_stats(datapath, ip, pkt, len(msg.data))
        
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _update_flow_stats(self, datapath, ip, pkt, packet_length):
        src_ip, dst_ip, protocol = ip.src, ip.dst, ip.proto
        flow_key = (src_ip, dst_ip, protocol)
        
        if protocol == 6:
            t = pkt.get_protocol(tcp.tcp)
            if t: flow_key = (src_ip, dst_ip, protocol, t.src_port, t.dst_port)
        elif protocol == 17:
            u = pkt.get_protocol(udp.udp)
            if u: flow_key = (src_ip, dst_ip, protocol, u.src_port, u.dst_port)

        current_time = time.time()
        
        if flow_key not in self.flow_table:
            self.flow_table[flow_key] = {
                'status': 'active', 'datapath': datapath, 'fwd_packet_count': 1, 
                'fwd_byte_count': packet_length, 'start_time': current_time, 
                'last_seen_time': current_time, 'syn_flag_count': 0, 'fin_flag_count': 0,
            }
        else:
            self.flow_table[flow_key]['fwd_packet_count'] += 1
            self.flow_table[flow_key]['fwd_byte_count'] += packet_length
            self.flow_table[flow_key]['last_seen_time'] = current_time

        if protocol == 6 and pkt.get_protocol(tcp.tcp):
            t = pkt.get_protocol(tcp.tcp)
            if t.bits & 0x02: self.flow_table[flow_key]['syn_flag_count'] += 1
            if t.bits & 0x01: self.flow_table[flow_key]['fin_flag_count'] += 1

    def _monitor(self):
        while True:
            with self.api_lock:
                stats = {'activeFlows': len(self.flow_table), 'mitigationCount': len(self.active_mitigations)}
                socketio.emit('updateStats', stats)
                
                timed_out_flows = []
                for flow_key, flow_stats in self.flow_table.items():
                    if time.time() - flow_stats['last_seen_time'] > 10 and flow_stats.get('status', 'active') == 'active':
                        timed_out_flows.append((flow_key, flow_stats))

                for src_ip, mitigation_data in list(self.active_mitigations.items()):
                    if time.time() - mitigation_data['timestamp'] > 60:
                        del self.active_mitigations[src_ip]
                        socketio.emit('mitigationRemoved', {'sourceIp': src_ip})
                
                for flow_key, flow_stats in list(self.flow_table.items()):
                    if flow_stats.get('status') == 'analyzed' and time.time() - flow_stats.get('analysis_time', 0) > 30:
                        del self.flow_table[flow_key]

            if timed_out_flows:
                if len(timed_out_flows) > 10: self.logger.warning("[ATTACK BEHAVIOR] %d flows timed out. Processing...", len(timed_out_flows))
                
                for flow_key, flow_stats in timed_out_flows:
                    feature_vector = self._calculate_features(flow_key, flow_stats)
                    datapath = flow_stats.get('datapath')
                    if datapath:
                        self._predict_and_mitigate(datapath, flow_key, feature_vector)
                    
                    with self.api_lock:
                        if flow_key in self.flow_table:
                             self.flow_table[flow_key]['status'] = 'analyzed'
                             self.flow_table[flow_key]['analysis_time'] = time.time()
            
            with self.api_lock:
                for victim_key, victim_data in list(self.victim_tracker.items()):
                    if time.time() - victim_data['last_seen'] > 20:
                        del self.victim_tracker[victim_key]
            
            hub.sleep(5)

    def _calculate_features(self, flow_key, flow_stats):
        flow_duration = flow_stats['last_seen_time'] - flow_stats['start_time']
        return {
            'Protocol': flow_key[2], 'Flow Duration': max(flow_duration, 1e-6),
            'Total Fwd Packets': flow_stats['fwd_packet_count'], 'Total Backward Packets': 0,
            'Fwd IAT Total': max(flow_duration, 1e-6),
            'Packet Length Mean': flow_stats['fwd_byte_count'] / flow_stats['fwd_packet_count'],
            'FIN Flag Count': flow_stats['fin_flag_count'], 'SYN Flag Count': flow_stats['syn_flag_count']
        }

    def _predict_and_mitigate(self, datapath, flow_key, features):
        if self.model is None: return

        try:
            feature_order = ['Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                             'Fwd IAT Total', 'Packet Length Mean', 'FIN Flag Count', 'SYN Flag Count']
            feature_values = [features[feature] for feature in feature_order]
            live_traffic_features = np.array(feature_values).reshape(1, -1)
            
            prediction = self.model.predict(live_traffic_features)
            confidence_scores = self.model.predict_proba(live_traffic_features)[0]
            attack_confidence = float(confidence_scores[1])
            
            socketio.emit('updateConfidence', {'confidence': attack_confidence})

            is_suspicious = (features['Total Fwd Packets'] <= 5 and features['SYN Flag Count'] >= 1)

            if prediction[0] == 1 and is_suspicious:
                if attack_confidence > 0.95: dynamic_flood_threshold = 20
                elif attack_confidence > 0.75: dynamic_flood_threshold = 50
                else: dynamic_flood_threshold = 100

                victim_key = (flow_key[1], flow_key[4] if len(flow_key) > 4 else 0)
                
                with self.api_lock:
                    if victim_key not in self.victim_tracker:
                        self.victim_tracker[victim_key] = {'count': 0, 'last_seen': time.time()}
                    self.victim_tracker[victim_key]['count'] += 1
                    self.victim_tracker[victim_key]['last_seen'] = time.time()
                    current_count = self.victim_tracker[victim_key]['count']
                
                self.logger.info("Suspicious SYN flow to %s. Confidence: %.2f. Count: %d. Threshold: %d",
                                 victim_key, attack_confidence, current_count, dynamic_flood_threshold)
                
                if current_count > dynamic_flood_threshold:
                    src_ip = flow_key[0]
                    victim_ip = victim_key[0]
                    
                    alert_data = {'type': 'DDoS ATTACK', 'severity': 'High', 'sourceIp': src_ip,
                                  'destination': f"{victim_key[0]}:{victim_key[1]}",
                                  'confidence': f"{attack_confidence:.2%}", 'timestamp': time.time()}
                    socketio.emit('newAlert', alert_data)
                    self.logger.info("🚨 HYBRID DETECTION: DDoS Flood Confirmed against %s 🚨", victim_key)
                    
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=victim_ip)
                    actions = []
                    self.add_flow(datapath, priority=ofproto.OFP_DEFAULT_PRIORITY + 10, match=match, actions=actions, hard_timeout=60)
                    
                    with self.api_lock:
                        mitigation_data = {'sourceIp': src_ip, 'type': 'Block', 'status': 'Active', 
                                           'timestamp': time.time(), 'victim': f"{victim_key[0]}:{victim_key[1]}"}
                        self.active_mitigations[src_ip] = mitigation_data
                        socketio.emit('newMitigation', mitigation_data)
                        self.logger.info("🛡️ MITIGATION ACTIVE: Blocking traffic from %s to %s for 60 seconds", src_ip, victim_ip)
                        self.victim_tracker[victim_key]['count'] = 0
            
            # --- FIX: THIS ELSE BLOCK WAS ACCIDENTALLY REMOVED. IT'S NOW RESTORED. ---
            else:
                # This block handles all non-suspicious or benign-predicted flows
                benign_confidence = float(confidence_scores[0])
                self.logger.info("✅ Flow Analyzed: Normal traffic. Confidence: %.2f", benign_confidence)

        except Exception as e:
            self.logger.error("Error in prediction/mitigation: %s", e)