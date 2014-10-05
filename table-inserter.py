# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu import utils


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.is_overflow = False
        self.mac_to_port = {}
        self.flow_table={}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        self.prior = True
        # del flows
        del_req = parser.OFPFlowMod(datapath=datapath,
                command = ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match, priority=35000)

        datapath.send_msg(del_req)
    
        # add default
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, ofproto.OFP_NO_BUFFER)
        self.rep_adding_flow(datapath, 1000)

    def add_flow(self, datapath, priority, match, actions, buffer_id, hard_timeout = 0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, hard_timeout=hard_timeout, 
                                priority=priority, buffer_id = buffer_id,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
                if self.is_overflow == False:
                    self.is_overflow = True
                    print "Packet-in overflow"
        else:
            self.is_overflow = False

        pkt = packet.Packet(msg.data)
  
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        if ethertype == ether.ETH_TYPE_ARP:
            self.handle_arp(datapath,msg,in_port)
            return

        if ethertype == ether.ETH_TYPE_IP:
            self.handle_ip(datapath,msg,in_port)
            return 

    def ipv4_to_int(self, string):
        ip = string.split('.')
        assert len(ip) == 4
        i = 0 
        for b in ip:
            b = int(b)
            i = (i<<8) | b
        return i

    # Ethernet - ARP
    def handle_arp(self,datapath,msg,in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath,msg.data, in_port)
        else:
            self.send_packet_out(datapath, msg.buffer_id, in_port)

    # Packet out
    def handle_no_buffer(self, datapath, data, in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
        req = ofp_parser.OFPPacketOut(datapath, ofp.OFP_NO_BUFFER, in_port, actions, data)
        datapath.send_msg(req)

    def send_packet_out(self, datapath, buffer_id, in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
        req = ofp_parser.OFPPacketOut(datapath, buffer_id, in_port, actions)
        datapath.send_msg(req)

    # Rep adding flow
    def rep_adding_flow(self, datapath, flow_no):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for i in range(flow_no):
            ipv4_src = "50.0.0.1"
            value = self.ipv4_to_int(ipv4_src)
            match = parser.OFPMatch()
            match.set_dl_type(ether.ETH_TYPE_IP)
            match.set_ipv4_src(value)
            ipv4_dst = "50.0.0.2"
            value = self.ipv4_to_int(ipv4_dst)+i
            match.set_ipv4_dst(value)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            if self.prior:
                self.add_flow(datapath, 1002-i, match, actions, ofproto.OFP_NO_BUFFER)
            else:
                self.add_flow(datapath, 1002-i, match, actions, ofproto.OFP_NO_BUFFER)

    # Ethernet - IP
    def handle_ip(self,datapath,msg,in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        #try to parse ip header
        pkt = packet.Packet(msg.data)
        ip_header = pkt.get_protocol(ipv4.ipv4)
        self.logger.debug('ip src %s dst %s', ip_header.src, ip_header.dst)
        ip_src = ip_header.src
        ip_dst = ip_header.dst

        #try to parse icmp
        if ip_header.proto == inet.IPPROTO_ICMP:
            self.handle_ping(datapath, msg, in_port)
            print "icmp recv"
            return
        else:
            print "ip recv"
            return

    # IP - TCP
    def handle_ping(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        match.set_ip_proto(inet.IPPROTO_ICMP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 100, match, actions, msg.buffer_id, 1)
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath,msg.data, in_port)
        else:
            self.send_packet_out(datapath, msg.buffer_id, in_port)
