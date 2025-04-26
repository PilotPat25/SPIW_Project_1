"""
 The script implements a simple controller for a network with 6 hosts and 5 switches.
 The switches are connected in a diamond topology (without vertical links):
    - 3 hosts are connected to the left (s1) and 3 to the right (s5) edge of the diamond.

 The overall operation of the controller is as follows:
    - wait for connection establishment from all switches in function _handle_ConnectionUp; therein, among others,
      start _timer_func() to cyclically chenge routing (see also below)
    - default routing is set in all switches on the reception of packet_in messages form the switch,
    - then the routing for (h1-h4) pair in switch s1 is changed every one second in a round-robin manner to
      load balance the traffic through switches s3, s4, s2. This is done in function _timer_func() that is
      triggered every second by a timer started in _handle_ConnectionUp, lines (around) 203-204
"""
import struct

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.packet_utils import *
import pox.lib.packet as pkt
from pox.lib.recoco import Timer
import time

log = core.getLogger()

# initialize global variables

# ids of connections to switches
s1_dpid = 0
s2_dpid = 0
s3_dpid = 0
s4_dpid = 0
s5_dpid = 0

# port statistics (number of packets sent or received) received from the switches in current step
s1_p1 = 0  # sent - Tx
s1_p4 = 0  # sent
s1_p5 = 0  # sent
s1_p6 = 0  # sent
s2_p1 = 0  # received - Rx
s3_p1 = 0  # received
s4_p1 = 0  # received

# port statistics (number of packets sent or received) received from the switch in previous step
pre_s1_p1 = 0  # sent
pre_s1_p4 = 0  # sent
pre_s1_p5 = 0  # sent
pre_s1_p6 = 0  # sent
pre_s2_p1 = 0  # received
pre_s3_p1 = 0  # received
pre_s4_p1 = 0  # received

start_time = 0.0
send_time1=0.0
send_time2=0.0
send_time3=0.0
send_time4=0.0
mytimer = 0
OWD1=0.0
OWD2_s2=0.0
OWD2_s3=0.0
OWD2_s4=0.0
delay_s2 = 200.0
delay_s3 = 50.0
delay_s4 = 10.0


# variable turn controls the round robin operation (takes value from the set 0,1,2)
turn = 0

# routing in the network changes every "routing_timer" seconds
routing_timer = 2

class myproto(packet_base):
  #My Protocol packet struct
  """
  myproto class defines our special type of packet to be sent all the way along including the link between the switches to measure link delays;
  it adds member attribute named timestamp to carry packet creation/sending time by the controller, and defines the
  function hdr() to return the header of measurement packet (header will contain timestamp)
  """
  #For more info on packet_base class refer to file pox/lib/packet/packet_base.py

  def __init__(self):
     packet_base.__init__(self)
     self.timestamp=0

  def hdr(self, payload):
     return struct.pack('!I', self.timestamp) # code as unsigned int (I), network byte order (!, big-endian - the most significant byte of a word at the smallest memory address)


def _handle_ConnectionDown (event):
  """Connection object (in the controller) represents the connection established with respective switch.
     Handle connection down - stop the timer for sending the probes, because conection to the switch has
     been terminated. It is fired when a connection to a switch has been terminated (either because it
     has been closed explicitly, because the switch was restarted, etc.)."""

  global mytimer
  print("ConnectionDown: ", dpidToStr(event.connection.dpid))
  mytimer.cancel()

def getTheTime():  # function to create a timestamp
    flock = time.localtime()
    then = "[%s-%s-%s" % (str(flock.tm_year), str(flock.tm_mon), str(flock.tm_mday))

    if int(flock.tm_hour) < 10:
        hrs = "0%s" % (str(flock.tm_hour))
    else:
        hrs = str(flock.tm_hour)
    if int(flock.tm_min) < 10:
        mins = "0%s" % (str(flock.tm_min))
    else:
        mins = str(flock.tm_min)

    if int(flock.tm_sec) < 10:
        secs = "0%s" % (str(flock.tm_sec))
    else:
        secs = str(flock.tm_sec)

    then += "]%s.%s.%s" % (hrs, mins, secs)
    return then


def _timer_func():
    # this function is called on 1-sec timer expiration and changes the routing
    global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid, turn, start_time, send_time1, send_time2, send_time3, send_time4

    if (core.openflow.getConnection(s1_dpid) is None):
        # this return avoids error notifications on stopping the network
        # (when connections disappear and getConnection() objects become Null)

        return
    if s1_dpid != 0 and not core.openflow.getConnection(s1_dpid) is None:
        # send out port_stats_request packet through switch0 connection src_dpid (to measure T1)
        core.openflow.getConnection(s1_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
        send_time1 = time.time() * 1000 * 10 - start_time  # sending time of stats_req: ctrl => switch0
        # print("send_time1:", send_time1)

        # sequence of packet formating operations optimised to reduce the delay variation of e-2-e measurements (to measure T3)
        f = myproto()  # create a probe packet object
        e = pkt.ethernet()  # create L2 type packet (frame) object
        e.src = EthAddr("0:0:0:0:0:2")
        e.dst = EthAddr("0:0:0:0:0:6")
        e.type = 0x5577  # set unregistered EtherType in L2 header type field, here assigned to the probe packet type
        msg = of.ofp_packet_out()  # create PACKET_OUT message object
        msg.actions.append(of.ofp_action_output(port=4))  # set the output port for the packet in switch0
        f.timestamp = int(time.time() * 1000 * 10 - start_time)  # set the timestamp in the probe packet
        # print(f.timestamp)
        e.payload = f
        msg.data = e.pack()
        core.openflow.getConnection(s1_dpid).send(msg)

        msg = of.ofp_packet_out()  # create PACKET_OUT message object
        msg.actions.append(of.ofp_action_output(port=5))  # set the output port for the packet in switch0
        f.timestamp = int(time.time() * 1000 * 10 - start_time)  # set the timestamp in the probe packet
        # print(f.timestamp)
        e.payload = f
        msg.data = e.pack()
        core.openflow.getConnection(s1_dpid).send(msg)

        msg = of.ofp_packet_out()  # create PACKET_OUT message object
        msg.actions.append(of.ofp_action_output(port=6))  # set the output port for the packet in switch0
        f.timestamp = int(time.time() * 1000 * 10 - start_time)  # set the timestamp in the probe packet
        # print(f.timestamp)
        e.payload = f
        msg.data = e.pack()
        core.openflow.getConnection(s1_dpid).send(msg)
    if s2_dpid != 0 and not core.openflow.getConnection(s2_dpid) is None:
        # send out port_stats_request packet through switch1 connection dst_dpid (to measure T2)
        core.openflow.getConnection(s2_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
        send_time2 = time.time() * 1000 * 10 - start_time  # sending time of stats_req: ctrl => switch1
        # print("send_time2:", send_time2)
    if s3_dpid != 0 and not core.openflow.getConnection(s3_dpid) is None:
        # send out port_stats_request packet through switch1 connection dst_dpid (to measure T2)
        core.openflow.getConnection(s3_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
        send_time3 = time.time() * 1000 * 10 - start_time  # sending time of stats_req: ctrl => switch1
        # print("send_time2:", send_time2)
    if s4_dpid != 0 and not core.openflow.getConnection(s4_dpid) is None:
        # send out port_stats_request packet through switch1 connection dst_dpid (to measure T2)
        core.openflow.getConnection(s4_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
        send_time4 = time.time() * 1000 * 10 - start_time  # sending time of stats_req: ctrl => switch1
        # print("send_time2:", send_time2)
    # core.openflow.getConnection(s1_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    # core.openflow.getConnection(s2_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    # core.openflow.getConnection(s3_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    # core.openflow.getConnection(s4_dpid).send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    # print( getTheTime(), "sent the port stats request to s1_dpid")

    # below, routing in s1 towards h4 (IP=10.0.0.4) is set according to the value of the variable turn
    # variable turn controls the round robin operation according to:
    #    turn=0/1/2 => route through s2/s3/s4, respectively

    # msg = of.ofp_flow_mod()
    # msg.command = of.OFPFC_MODIFY_STRICT
    # msg.priority = 100
    # msg.idle_timeout = 0
    # msg.hard_timeout = 0
    # msg.match.dl_type = 0x0800
    # msg.match.nw_tos = 0x00
    # msg.actions.append(of.ofp_action_output(port=6))
    # core.openflow.getConnection(s1_dpid).send(msg)
    #
    #
    # msg = of.ofp_flow_mod()
    # msg.command = of.OFPFC_MODIFY_STRICT
    # msg.priority = 100
    # msg.idle_timeout = 0
    # msg.hard_timeout = 0
    # msg.match.dl_type = 0x0800
    # msg.match.nw_tos = 0x50
    # msg.actions.append(of.ofp_action_output(port=5))
    # core.openflow.getConnection(s1_dpid).send(msg)
    #
    #
    # msg = of.ofp_flow_mod()
    # msg.command = of.OFPFC_MODIFY_STRICT
    # msg.priority = 100
    # msg.idle_timeout = 0
    # msg.hard_timeout = 0
    # msg.match.dl_type = 0x0800
    # msg.match.nw_tos = 0x96
    # msg.actions.append(of.ofp_action_output(port=4))
    # core.openflow.getConnection(s1_dpid).send(msg)




def _handle_portstats_received(event):
    # Handling of port statistics retrieved from switches.
    # Observe the use of port statistics here
    # Note: based on https://github.com/tsartsaris/pythess-SDN/blob/master/pythess.py

    global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid
    global s1_p1, s1_p4, s1_p5, s1_p6, s2_p1, s3_p1, s4_p1
    global pre_s1_p1, pre_s1_p4, pre_s1_p5, pre_s1_p6, pre_s2_p1, pre_s3_p1, pre_s4_p1
    global start_time, send_time1, send_time2, send_time3, send_time4, OWD1, OWD2_s2, OWD2_s3, OWD2_s4

    print("===>Event.stats:")
    print(event.stats)
    print("<===")
    received_time = time.time() * 1000 * 10 - start_time
    if event.connection.dpid == s1_dpid:  # The DPID of one of the switches involved in the link
        OWD1 = 0.5 * (received_time - send_time1)
        for f in event.stats:
            if int(f.port_no) < 65534:
                if f.port_no == 1:
                    pre_s1_p1 = s1_p1
                    s1_p1 = f.rx_packets
                    # print( "s1_p1->", s1_p1, "TxDrop:", f.tx_dropped,"RxDrop:",f.rx_dropped,"TxErr:",f.tx_errors,"CRC:",f.rx_crc_err,"Coll:",f.collisions,"Tx:",f.tx_packets,"Rx:",f.rx_packets)
                if f.port_no == 4:
                    pre_s1_p4 = s1_p4
                    s1_p4 = f.tx_packets
                    # s1_p4=f.tx_bytes
                    # print( "s1_p4->", s1_p4, "TxDrop:", f.tx_dropped,"RxDrop:",f.rx_dropped,"TxErr:",f.tx_errors,"CRC:",f.rx_crc_err,"Coll:",f.collisions,"Tx:",f.tx_packets,"Rx:",f.rx_packets)
                if f.port_no == 5:
                    pre_s1_p5 = s1_p5
                    s1_p5 = f.tx_packets
                if f.port_no == 6:
                    pre_s1_p6 = s1_p6
                    s1_p6 = f.tx_packets

    if event.connection.dpid == s2_dpid:
        OWD2_s2 = 0.5 * (received_time - send_time2)
        for f in event.stats:
            if int(f.port_no) < 65534:
                if f.port_no == 1:
                    pre_s2_p1 = s2_p1
                    s2_p1 = f.rx_packets
                    # s2_p1=f.rx_bytes
        print(getTheTime(), "s1_p4(Sent):", (s1_p4 - pre_s1_p4), "s2_p1(Received):", (s2_p1 - pre_s2_p1))

    if event.connection.dpid == s3_dpid:
        OWD2_s3 = 0.5 * (received_time - send_time3)
        for f in event.stats:
            if int(f.port_no) < 65534:
                if f.port_no == 1:
                    pre_s3_p1 = s3_p1
                    s3_p1 = f.rx_packets
        print(getTheTime(), "s1_p5(Sent):", (s1_p5 - pre_s1_p5), "s3_p1(Received):", (s3_p1 - pre_s3_p1))

    if event.connection.dpid == s4_dpid:
        OWD2_s4 = 0.5 * (received_time - send_time4)
        for f in event.stats:
            if int(f.port_no) < 65534:
                if f.port_no == 1:
                    pre_s4_p1 = s4_p1
                    s4_p1 = f.rx_packets
        print(getTheTime(), "s1_p6(Sent):", (s1_p6 - pre_s1_p6), "s4_p1(Received):", (s4_p1 - pre_s4_p1))


def _handle_ConnectionUp(event):
    # waits for connections from the switches, and after connecting all of them it starts a round robin timer for triggering h1-h4 routing changes
    global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid, mytimer
    print("ConnectionUp: ", dpidToStr(event.connection.dpid))

    # remember the connection dpid for the switch
    for m in event.connection.features.ports:
        if m.name == "s1-eth1":
            # s1_dpid: the DPID (datapath ID) of switch s1;
            s1_dpid = event.connection.dpid
            print("s1_dpid=", s1_dpid)
        elif m.name == "s2-eth1":
            s2_dpid = event.connection.dpid
            print("s2_dpid=", s2_dpid)
        elif m.name == "s3-eth1":
            s3_dpid = event.connection.dpid
            print("s3_dpid=", s3_dpid)
        elif m.name == "s4-eth1":
            s4_dpid = event.connection.dpid
            print("s4_dpid=", s4_dpid)
        elif m.name == "s5-eth1":
            s5_dpid = event.connection.dpid
            print("s5_dpid=", s5_dpid)

    # if all switches are connected, start 1-second recurring loop timer for round-robin routing changes;
    # _timer_func is to be called on timer expiration to change the flow entry in s1
    if s1_dpid != 0 and s2_dpid != 0 and s3_dpid != 0 and s4_dpid != 0 and s5_dpid != 0:
        mytimer=Timer(routing_timer, _timer_func, recurring=True)


def _handle_PacketIn(event):
    global s1_dpid, s2_dpid, s3_dpid, s4_dpid, s5_dpid, start_time, OWD1, OWD2_s2, OWD2_s3, OWD2_s4, delay_s2, delay_s3, delay_s4, s1_p6, pre_s1_p6, s1_p5, pre_s1_p5

    packet = event.parsed
    # print( "_handle_PacketIn is called, packet.type:", packet.type, " event.connection.dpid:", event.connection.dpid)

    # Below, set the default/initial routing rules for all switches and ports.
    # All rules are set up in a given switch on packet_in event received from the switch which means no flow entry has been found in the flow table.
    # This setting up may happen either at the very first pactet being sent or after flow entry expirationn inn the switch


    if event.connection.dpid == s1_dpid:
        a = packet.find(
            'arp')  # If packet object does not encapsulate a packet of the type indicated, find() returns None
        if a and a.protodst == "10.0.0.4":
            msg = of.ofp_packet_out(
                data=event.ofp)  # Create packet_out message; use the incoming packet as the data for the packet out
            msg.actions.append(of.ofp_action_output(port=4))  # Add an action to send to the specified port
            event.connection.send(msg)  # Send message to switch

        if a and a.protodst == "10.0.0.5":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=5))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.6":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=6))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.1":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=1))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.2":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=2))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.3":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=3))
            event.connection.send(msg)



        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800  # rule for IP packets (x0800)
        msg.match.nw_dst = "10.0.0.1"
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = "10.0.0.2"
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = "10.0.0.3"
        msg.actions.append(of.ofp_action_output(port=3))
        event.connection.send(msg)

        ip = packet.find("ipv4")
        # if ip is not None:
        #     print("IPv4 packet")
        if ip and ((delay_s4 <= ip.tos <= delay_s3) or ((delay_s3 <= ip.tos <= delay_s2)and (s1_p6 - pre_s1_p6) < 100)):
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.idle_timeout = 5
            msg.hard_timeout = 10
            msg.match.nw_tos = ip.tos
            msg.match.dl_type = 0x0800
            msg.actions.append(of.ofp_action_output(port=6))
            event.connection.send(msg)
            return
        if ip and ((delay_s3 <= ip.tos <= delay_s2) or ((ip.tos > delay_s2)and(s1_p5 - pre_s1_p5)<200)):
            # print(hex(ip.tos))
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.idle_timeout = 10
            msg.hard_timeout = 20
            msg.match.nw_tos = ip.tos
            msg.match.dl_type = 0x0800
            msg.actions.append(of.ofp_action_output(port=5))
            event.connection.send(msg)
            return
        if ip and (ip.tos == 0 or ip.tos > delay_s2):
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.idle_timeout = 20
            msg.hard_timeout = 40
            msg.match.nw_tos = ip.tos
            msg.match.dl_type = 0x0800
            msg.actions.append(of.ofp_action_output(port=4))
            event.connection.send(msg)
            return


    elif event.connection.dpid == s2_dpid:
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 1
        msg.match.dl_type = 0x0806  # rule for ARP packets (x0806)
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 1
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 2
        msg.match.dl_type = 0x0806
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 2
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)

        if packet.type == 0x5577:  # 0x5577 is unregistered EtherType, here assigned to probe packets
            """Process a probe packet received in PACKET_IN message from 'switch1' (dst_dpid),
               previously sent to 'switch0' (src_dpid) in PACKET_OUT."""
            received_time = time.time() * 1000 * 10 - start_time

            c = packet.find('ethernet').payload
            d, = struct.unpack('!I', c)  # note that d,=... is a struct.unpack and always returns a tuple
            delay_s2 = int(received_time - d - OWD1 - OWD2_s2) / 10
            print("[ms*10]: received_time=", int(received_time), ", d=", d, ", OWD1=", int(OWD1), ", OWD2=", int(OWD2_s2))
            print("delay for s2:", delay_s2,
                  "[ms] <=====")  # divide by 10 to normalise to milliseconds
    elif event.connection.dpid == s3_dpid:
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 1
        msg.match.dl_type = 0x0806
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 1
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 2
        msg.match.dl_type = 0x0806
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 2
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)
        if packet.type == 0x5577:  # 0x5577 is unregistered EtherType, here assigned to probe packets
            """Process a probe packet received in PACKET_IN message from 'switch1' (dst_dpid),
               previously sent to 'switch0' (src_dpid) in PACKET_OUT."""
            received_time = time.time() * 1000 * 10 - start_time
            c = packet.find('ethernet').payload
            d, = struct.unpack('!I', c)  # note that d,=... is a struct.unpack and always returns a tuple
            delay_s3 = int(received_time - d - OWD1 - OWD2_s3) / 10
            print("[ms*10]: received_time=", int(received_time), ", d=", d, ", OWD1=", int(OWD1), ", OWD2=", int(OWD2_s3))
            print("delay for s3:", delay_s3,
                  "[ms] <=====")  # divide by 10 to normalise to milliseconds
    elif event.connection.dpid == s4_dpid:
        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 1
        msg.match.dl_type = 0x0806
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 1
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 2
        msg.match.dl_type = 0x0806
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 10
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.in_port = 2
        msg.match.dl_type = 0x0800
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)
        if packet.type == 0x5577:  # 0x5577 is unregistered EtherType, here assigned to probe packets
            """Process a probe packet received in PACKET_IN message from 'switch1' (dst_dpid),
               previously sent to 'switch0' (src_dpid) in PACKET_OUT."""
            received_time = time.time() * 1000 * 10 - start_time
            c = packet.find('ethernet').payload
            d, = struct.unpack('!I', c)  # note that d,=... is a struct.unpack and always returns a tuple
            delay_s4 = int(received_time - d - OWD1 - OWD2_s4) / 10
            print("[ms*10]: received_time=", int(received_time), ", d=", d, ", OWD1=", int(OWD1), ", OWD2=", int(OWD2_s4))
            print("delay for s4:", delay_s4,
                  "[ms] <=====")  # divide by 10 to normalise to milliseconds
    elif event.connection.dpid == s5_dpid:
        a = packet.find('arp')
        if a and a.protodst == "10.0.0.4":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=4))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.5":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=5))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.6":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=6))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.1":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=1))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.2":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=2))
            event.connection.send(msg)

        if a and a.protodst == "10.0.0.3":
            msg = of.ofp_packet_out(data=event.ofp)
            msg.actions.append(of.ofp_action_output(port=3))
            event.connection.send(msg)


        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = "10.0.0.1"
        msg.actions.append(of.ofp_action_output(port=1))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = "10.0.0.2"
        msg.actions.append(of.ofp_action_output(port=2))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = "10.0.0.3"
        msg.actions.append(of.ofp_action_output(port=3))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = "10.0.0.4"
        msg.actions.append(of.ofp_action_output(port=4))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = "10.0.0.5"
        msg.actions.append(of.ofp_action_output(port=5))
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        msg.match.dl_type = 0x0800
        msg.match.nw_dst = "10.0.0.6"
        msg.actions.append(of.ofp_action_output(port=6))
        event.connection.send(msg)


def launch():
    """
    As usually, launch() is the function called by POX to initialize the
    component indicated by a parameter provided to pox.py (routing_controller.py in
    our case). For more info, see
    http://intronetworks.cs.luc.edu/auxiliary_files/mininet/poxwiki.pdf
    """

    global start_time
    start_time = time.time() * 1000 * 10
    """core is an instance of class POXCore (EventMixin) and it can register objects.
       An object with name xxx can be registered to core instance which makes this
       object become a "component" available as pox.core.core.xxx. For examples, see,
       e.g., https://noxrepo.github.io/pox-doc/html/#the-openflow-nexus-core-openflow """
    core.openflow.addListenerByName("PortStatsReceived",
                                    _handle_portstats_received)  # listen for port stats , https://noxrepo.github.io/pox-doc/html/#statistics-events
    core.openflow.addListenerByName("ConnectionDown", _handle_ConnectionDown)
    core.openflow.addListenerByName("ConnectionUp",
                                    _handle_ConnectionUp)  # listen for the establishment of a new control channel with a switch, https://noxrepo.github.io/pox-doc/html/#connectionup
    core.openflow.addListenerByName("PacketIn",
                                    _handle_PacketIn)  # listen for the reception of packet_in message from switch, https://noxrepo.github.io/pox-doc/html/#packetin

