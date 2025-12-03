import argparse
import os
from argparse import Namespace

import scapy.all as scapy


class SSIDChanger:
    def __init__(
        self, input_pcap: str, exclude_ssid: list = [], output_pcap: str = None
    ) -> None:
        if os.path.isfile(input_pcap):
            self.input_pcap = input_pcap
        else:
            raise "File not found at {input_pcap}"

        self.pkts = scapy.RawPcapReader(input_pcap)

        if not output_pcap:
            base, ext = os.path.splitext(self.input_pcap)
            self.output_pcap = f"{base}_modified{ext}"
        else:
            self.output_pcap = output_pcap

        self.out_pkts = scapy.RawPcapWriter(self.output_pcap)

        self.exclude_ssid = exclude_ssid
        self.new_ssids = {}

    def set_SSID(self) -> None:
        for raw_pkt, _ in self.pkts:
            pkt = scapy.Dot11(raw_pkt)

            if pkt.haslayer(scapy.Dot11ProbeResp):
                layer = pkt.getlayer(scapy.Dot11Elt)
            elif pkt.haslayer(scapy.Dot11Beacon):
                layer = pkt.getlayer(scapy.Dot11Beacon)
            else:
                self.out_pkts.write(pkt)
                continue

            original_ssid = layer.info.decode()
            if original_ssid in self.exclude_ssid:
                self.out_pkts.write(pkt)
                continue

            new_ssid = self.ask_for_SSID(original_ssid)
            layer.len = len(new_ssid)
            layer.info = new_ssid.encode()

            self.out_pkts._write_packet(pkt, 1, caplen=len(pkt), wirelen=len(pkt))

        print("Modified PCAP written to:", self.output_pcap)

    def ask_for_SSID(self, current_ssid: str) -> str:
        if current_ssid in self.new_ssids:
            return self.new_ssids[current_ssid]

        while True:
            new_ssid: str = input(
                f"Give a SSID name to replace {current_ssid.encode()}: "
            )

            if any(
                renamed_ssid == new_ssid and original_ssid != current_ssid
                for original_ssid, renamed_ssid in self.new_ssids.items()
            ):
                print("Name already given to another SSID.")
                continue

            self.new_ssids[current_ssid] = new_ssid
            return new_ssid


def parse_args() -> Namespace:
    parser = argparse.ArgumentParser(
        description="Modify SSIDs in a pcap by interactively providing replacements."
    )

    parser.add_argument(
        "-f", "--file", required=True, help="Input pcap file to process"
    )

    parser.add_argument(
        "-e",
        "--exclude",
        nargs="*",
        default=[],
        help="SSID names to exclude from modification (space-separated list)",
    )

    parser.add_argument("-o", "--output", help="Output pcap filename (optional)")

    return parser.parse_args()


if __name__ == "__main__":
    args: Namespace = parse_args()

    ssidchanger = SSIDChanger(
        input_pcap=args.file, exclude_ssid=args.exclude, output_pcap=args.output
    )
    ssidchanger.set_SSID()
