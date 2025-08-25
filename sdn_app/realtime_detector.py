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

class RealtimeDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RealtimeDetector, self).__init__(*args, **kwargs)
        # This will be our table to store flow statistics
        self.flow_table = {}
        self.mac_to_port = {}
        self.logger.info("SDN DDoS Detector Application Started.")
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch features event. Install table-miss flow entry."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install a rule to send any packet that doesn't match other rules to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Default flow rule installed on switch %s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        """Helper function to add a flow rule to a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, 
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle incoming packets and update flow statistics."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)

        # Get input port
        in_port = msg.match['in_port']
        
        # Learn MAC addresses to avoid FLOOD next time
        if eth.src not in self.mac_to_port:
            self.mac_to_port[eth.src] = in_port

        # Determine output port
        if eth.dst in self.mac_to_port:
            out_port = self.mac_to_port[eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # Create actions for packet forwarding
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install a flow rule to avoid packet_in next time for this flow
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            # Add flow rule with idle timeout
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id, idle_timeout=10)
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=10)

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        # Now do our flow analysis for IP packets
        if ip:
            src_ip = ip.src
            dst_ip = ip.dst
            protocol = ip.proto
            
            # Create a unique key for the flow (forward direction)
            flow_key = (src_ip, dst_ip, protocol)
            
            # Try to get TCP/UDP ports if they exist
            if protocol == 6: # TCP
                t = pkt.get_protocol(tcp.tcp)
                if t:
                    flow_key = (src_ip, dst_ip, protocol, t.src_port, t.dst_port)
            elif protocol == 17: # UDP
                u = pkt.get_protocol(udp.udp)
                if u:
                    flow_key = (src_ip, dst_ip, protocol, u.src_port, u.dst_port)

            # Current timestamp
            current_time = time.time()
            packet_length = len(msg.data)

            # Check if flow is new or existing
            if flow_key not in self.flow_table:
                # This is a new flow, initialize its stats
                self.flow_table[flow_key] = {
                    'fwd_packet_count': 1,
                    'fwd_byte_count': packet_length,
                    'start_time': current_time,
                    'last_seen_time': current_time,
                    # Add counters for flags
                    'syn_flag_count': 0,
                    'fin_flag_count': 0,
                }
            else:
                # This is an existing flow, update its stats
                self.flow_table[flow_key]['fwd_packet_count'] += 1
                self.flow_table[flow_key]['fwd_byte_count'] += packet_length
                self.flow_table[flow_key]['last_seen_time'] = current_time

            # Count TCP flags if it's a TCP packet
            if protocol == 6:
                t = pkt.get_protocol(tcp.tcp)
                if t:
                    if t.bits & 0x02: # SYN flag
                        self.flow_table[flow_key]['syn_flag_count'] += 1
                    if t.bits & 0x01: # FIN flag
                        self.flow_table[flow_key]['fin_flag_count'] += 1

    def _monitor(self):
        """Background thread to monitor flows and check for timeouts."""
        while True:
            # Check for timed-out flows every 5 seconds
            for flow_key, flow_stats in list(self.flow_table.items()):
                # If no packet has been seen for 10 seconds, consider the flow timed out
                if time.time() - flow_stats['last_seen_time'] > 10:
                    self.logger.info("Flow timed out: %s", flow_key)
                    
                    # Calculate final features for the model
                    feature_vector = self._calculate_features(flow_key, flow_stats)
                    
                    # Pass features to the placeholder prediction function
                    self._predict_and_mitigate(feature_vector)

                    # Remove the flow from our table
                    del self.flow_table[flow_key]
            
            # Sleep for a bit before checking again
            hub.sleep(5)

    def _calculate_features(self, flow_key, flow_stats):
        """Calculate the feature vector from the flow's final stats."""
        # This is where you implement the "contract"
        flow_duration = flow_stats['last_seen_time'] - flow_stats['start_time']
        
        # Avoid division by zero if duration is 0
        if flow_duration == 0:
            flow_duration = 0.000001
            
        # Extract protocol from flow_key
        protocol = flow_key[2] if len(flow_key) > 2 else 0
            
        feature_vector = {
            'Protocol': protocol,
            'Flow Duration': flow_duration,
            'Total Fwd Packets': flow_stats['fwd_packet_count'],
            'Total Backward Packets': 0, # Placeholder, needs bwd flow logic
            'Fwd IAT Total': flow_duration, # Simplified for now
            'Packet Length Mean': flow_stats['fwd_byte_count'] / flow_stats['fwd_packet_count'],
            'FIN Flag Count': flow_stats['fin_flag_count'],
            'SYN Flag Count': flow_stats['syn_flag_count']
        }
        return feature_vector

    def _predict_and_mitigate(self, features):
        """Placeholder for ML prediction and mitigation."""
        print("="*50)
        print("FLOW TIMED OUT. READY FOR ML PREDICTION.")
        print("Collected Features:", features)
        print("="*50)