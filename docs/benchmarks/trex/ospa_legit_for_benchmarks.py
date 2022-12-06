# Modified from xdp-paper
# https://github.com/tohojo/xdp-paper/blob/master/benchmarks/udp_for_benchmarks.py
# to also vary UDP sport when running multiple streams
from trex_stl_lib.api import *

class STLS1(object):
    def create_stream (self, packet_len, stream_count):
        packets = []
        for i in range(stream_count):
            base_pkt = Ether()/IP(src="10.229.220.3",dst="10.229.220.1")/UDP(dport=22211,sport=2024+i)
            base_pkt_len = len(base_pkt)
            base_pkt /= self.get_ospa_packet_data()
            #base_pkt /= 'x' * max(0, packet_len - base_pkt_len)
            packets.append(STLStream(
                packet = STLPktBuilder(pkt = base_pkt),
                mode = STLTXCont()
                ))
        return packets

    def get_streams (self, direction = 0, packet_len = 64, stream_count = 1, **kwargs):
        # create 1 stream
        return self.create_stream(packet_len - 4, stream_count)

    def get_ospa_packet_data(self):
        f = open("./ospa/ospa_req_legit.bin", "rb")
        data = f.read()
        f.close()
        return data

# dynamic load - used for trex console or simulator
def register():
    return STLS1()

