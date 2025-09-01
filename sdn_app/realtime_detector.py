"""
An advanced SDN application for real-time DDoS detection using a 
two-stage hybrid algorithm.

Stage 1: A specialized Machine Learning model (Random Forest) provides a fast
         initial classification for each network flow.
Stage 2: A stateful, heuristic supervisor analyzes the ML model's output and
         confidence, using an adaptive threshold to confirm volumetric attacks
         like SYN floods, thereby reducing false positives and enabling robust
         detection.
"""
# Import necessary Ryu libraries
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub

# Import standard Python libraries
import time
import joblib
import numpy as np
import os

# Just after the existing imports at the top of the file

# --- CORRECTED CODE BLOCK ---
import warnings
# InconsistentVersionWarning is specific to scikit-learn
from sklearn.exceptions import InconsistentVersionWarning

# UserWarning is a built-in Python warning, so it does not need to be imported.

# Suppress specific warnings from scikit-learn for a cleaner log
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')
warnings.filterwarnings("ignore", category=InconsistentVersionWarning, module='sklearn')
# --------------------------

class RealtimeDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RealtimeDetector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.flow_table = {}
        
        # --- HYBRID ALGORITHM DATA STRUCTURE ---
        # This tracks potential victims based on suspicious flow counts.
        # Key: (victim_ip, victim_port), Value: {'count': count, 'last_seen': timestamp}
        self.victim_tracker = {}
        # -------------------------------------

        self.logger.info("SDN DDoS Detector Application Started.")
        
        # --- LOAD THE SPECIALIZED ML MODEL ---
        model_path = 'models/syn_flood_model.joblib'
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                self.logger.info("ML Model loaded successfully from %s", model_path)
            except Exception as e:
                self.logger.error("Failed to load ML model: %s", e)
                self.model = None
        else:
            self.logger.warning("ML model not found at %s. Running in monitoring mode only.", model_path)
            self.model = None
        
        self.monitor_thread = hub.spawn(self._monitor)

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
        mod_args = {
            'datapath': datapath,
            'priority': priority,
            'match': match,
            'instructions': inst,
            'idle_timeout': idle_timeout,
            'hard_timeout': hard_timeout
        }
        if buffer_id:
            mod_args['buffer_id'] = buffer_id
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
        
        # --- L2 Learning Switch Logic ---
        # learns mac address to avoid FLOOD next time.
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port
        
        if eth.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]

        # --- BLOCK REMOVED ---
        # The code that installed a proactive flow rule was here.
        # It has been removed to ensure the controller sees more packets
        # from each flow for better analysis, at the cost of higher CPU load.
        
        # --- Real-time Feature Extraction Logic ---
        ip = pkt.get_protocol(ipv4.ipv4)
        if ip:
            self._update_flow_stats(datapath, ip, pkt, len(msg.data))
        
        # --- Forward the Packet ---
        # Instruct the switch to send this specific packet out.
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _update_flow_stats(self, datapath, ip, pkt, packet_length):
        src_ip, dst_ip, protocol = ip.src, ip.dst, ip.proto
        flow_key = (src_ip, dst_ip, protocol)
        
        if protocol == 6: # TCP
            t = pkt.get_protocol(tcp.tcp)
            if t: flow_key = (src_ip, dst_ip, protocol, t.src_port, t.dst_port)
        elif protocol == 17: # UDP
            u = pkt.get_protocol(udp.udp)
            if u: flow_key = (src_ip, dst_ip, protocol, u.src_port, u.dst_port)

        current_time = time.time()
        
        if flow_key not in self.flow_table:
            self.flow_table[flow_key] = {
                'datapath': datapath, 'fwd_packet_count': 1, 'fwd_byte_count': packet_length,
                'start_time': current_time, 'last_seen_time': current_time,
                'syn_flag_count': 0, 'fin_flag_count': 0,
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
        """Background thread to monitor flows, provide status, and check for timeouts."""
        while True:
            # Provide a periodic status update of currently active flows
            self.logger.info("Monitoring... Currently tracking %d active flows.", len(self.flow_table))
            
            # --- NEW: Collect all timed-out flows first ---
            timed_out_flows = []
            for flow_key, flow_stats in list(self.flow_table.items()):
                if time.time() - flow_stats['last_seen_time'] > 10: # Flow timeout = 10s
                    timed_out_flows.append((flow_key, flow_stats))

            # --- NEW: Implement Smart Logging ---
            # If a large number of flows time out at once, it's likely a flood.
            # In this case, print a summary instead of logging each one individually.
            LOGGING_THRESHOLD = 10 
            if len(timed_out_flows) > LOGGING_THRESHOLD:
                self.logger.warning("[ATTACK BEHAVIOR] %d flows timed out simultaneously. Processing...", len(timed_out_flows))

            # Now, process all the timed-out flows for detection
            for flow_key, flow_stats in timed_out_flows:
                # Use detailed logging only if we are below the threshold
                if len(timed_out_flows) <= LOGGING_THRESHOLD:
                    self.logger.info("Flow timed out: %s", flow_key)
                
                # The core detection logic remains the same
                feature_vector = self._calculate_features(flow_key, flow_stats)
                datapath = flow_stats.get('datapath')
                if datapath:
                    self._predict_and_mitigate(datapath, flow_key, feature_vector)

                # Remove the processed flow from the main table
                del self.flow_table[flow_key]
            
            # Periodically clean up old victim tracker entries
            for victim_key, victim_data in list(self.victim_tracker.items()):
                if time.time() - victim_data['last_seen'] > 60: # Cleanup after 1 min
                    del self.victim_tracker[victim_key]
            
            hub.sleep(5)

    def _calculate_features(self, flow_key, flow_stats):
        flow_duration = flow_stats['last_seen_time'] - flow_stats['start_time']
        flow_duration = max(flow_duration, 1e-6) # Avoid division by zero
        
        return {
            'Protocol': flow_key[2],
            'Flow Duration': flow_duration,
            'Total Fwd Packets': flow_stats['fwd_packet_count'],
            'Total Backward Packets': 0, # Placeholder
            'Fwd IAT Total': flow_duration, # Simplified
            'Packet Length Mean': flow_stats['fwd_byte_count'] / flow_stats['fwd_packet_count'],
            'FIN Flag Count': flow_stats['fin_flag_count'],
            'SYN Flag Count': flow_stats['syn_flag_count']
        }

    def _predict_and_mitigate(self, datapath, flow_key, features):
        if self.model is None: return

        try:
            # --- STAGE 1: ML PREDICTION ---
            feature_order = ['Protocol', 'Flow Duration', 'Total Fwd Packets',
                             'Total Backward Packets', 'Fwd IAT Total',
                             'Packet Length Mean', 'FIN Flag Count', 'SYN Flag Count']
            feature_values = [features[feature] for feature in feature_order]
            live_traffic_features = np.array(feature_values).reshape(1, -1)
            
            prediction = self.model.predict(live_traffic_features)
            confidence = self.model.predict_proba(live_traffic_features)[0]

            # --- STAGE 2: HYBRID ALGORITHM LOGIC ---
            is_suspicious = (features['Total Fwd Packets'] <= 5 and features['SYN Flag Count'] >= 1)

            if prediction[0] == 1 and is_suspicious:
                # --- ADAPTIVE THRESHOLDING (The "AI Era" Upgrade) ---
                attack_confidence = confidence[1] # Probability of being a DDoS attack
                
                if attack_confidence > 0.95:
                    dynamic_flood_threshold = 20  # High confidence -> Be aggressive
                elif attack_confidence > 0.75:
                    dynamic_flood_threshold = 50  # Medium confidence -> Standard
                else:
                    dynamic_flood_threshold = 100 # Low confidence -> Be cautious

                victim_key = (flow_key[1], flow_key[4] if len(flow_key) > 4 else 0)
                
                if victim_key not in self.victim_tracker:
                    self.victim_tracker[victim_key] = {'count': 0, 'last_seen': time.time()}
                
                self.victim_tracker[victim_key]['count'] += 1
                self.victim_tracker[victim_key]['last_seen'] = time.time()

                self.logger.info("Suspicious SYN flow to %s. Confidence: %.2f. Count: %d. Threshold: %d",
                                 victim_key, attack_confidence, self.victim_tracker[victim_key]['count'], dynamic_flood_threshold)
                
                if self.victim_tracker[victim_key]['count'] > dynamic_flood_threshold:
                    self.logger.info("🚨 HYBRID DETECTION: DDoS Flood Confirmed against %s 🚨", victim_key)
                    # For this project, we block the source of the triggering flow
                    src_ip = flow_key[0]
                    parser = datapath.ofproto_parser
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                    actions = [] # Empty action list means DROP
                    self.add_flow(datapath, priority=2, match=match, actions=actions, hard_timeout=60)
                    self.logger.info("🛡️ MITIGATION ACTIVE: Blocking traffic from %s for 60 seconds", src_ip)
                    # Reset counter to prevent log spam
                    self.victim_tracker[victim_key]['count'] = 0

        except Exception as e:
            self.logger.error("Error in prediction/mitigation: %s", e)