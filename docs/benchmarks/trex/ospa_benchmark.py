# Modified from xdp-paper
# https://github.com/tohojo/xdp-paper/blob/master/benchmarks/udp_for_benchmarks.py
# to also vary UDP sport when running multiple streams
from trex_stl_lib.api import *

# Tunables:
#   * d_stream_count = DoS streams
#   * l_stream_count = Legit streams
#   * l_pps = Legit packets per second
#   * l_payload = Legit stream payload path (e.g. ./ospa/ospa_req_legit.bin)
#

class STLS1(object):
    def create_stream(self, d_stream_count, l_stream_count, l_payload, l_pps):
        packets = []

        for i in range(l_stream_count):
            base_pkt = Ether()/IP(src="10.229.220.2",dst="10.229.220.1")/UDP(dport=22211,sport=2024+i)

            f = open(l_payload, "rb")
            data = f.read()
            f.close()

            base_pkt /= data
            packets.append(STLStream(
                packet = STLPktBuilder(pkt = base_pkt),
                mode = STLTXCont(pps = l_pps)
                ))


        for i in range(d_stream_count):
            base_pkt = Ether()/IP(src="10.229.220.2",dst="10.229.220.1")/UDP(dport=22211,sport=2024+i)
            base_pkt /= self.get_dos_ospa_packet_data()
            packets.append(STLStream(
                packet = STLPktBuilder(pkt = base_pkt),
                mode = STLTXCont()
                ))

        return packets

    def get_streams(self, d_stream_count = 1, l_stream_count = 1, l_pps = 1, l_payload="./ospa/ospa_req_legit.bin",  **kwargs):
        return self.create_stream(d_stream_count, l_stream_count, l_pps, l_payload)

    def get_dos_ospa_packet_data(self):
        return bytes([
                 0x20, 0x42, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, # OpenSPA header (request, v2, RSA cipher)
                 0x01, 0x02, 0x42, 0x24, # Encrypted Payload TLV entry
                 # Encrypted session (decrypt using RSA) TLV entry
                 0x02, 0x24,
                 0x24, 0x42, 0x32, 0x77, 0xf1, 0xab, 0x97, 0x11,
                 0x72, 0x30, 0x89, 0xa3, 0x47, 0x58, 0x47, 0x32,
                 0xa8, 0x04, 0x3c, 0x75, 0x09, 0x45, 0x9b, 0x80,
                 0x43, 0x5f, 0x03, 0x47, 0x0e, 0x9f, 0xe3, 0xff,
                 0x50, 0x21, 0x08, 0x44
               ])

# dynamic load - used for trex console or simulator
def register():
    return STLS1()

