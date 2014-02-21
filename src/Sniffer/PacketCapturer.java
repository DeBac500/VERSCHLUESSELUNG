package Sniffer;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
 
public class PacketCapturer {
 
    public static void main(String[] args) {
        try {
            // Will be filled with NICs
            List alldevs = new ArrayList();
 
            // For any error msgs
            StringBuilder errbuf = new StringBuilder();
 
            //Getting a list of devices
            int r = Pcap.findAllDevs(alldevs, errbuf);
            System.out.println(r);
            if (r != Pcap.OK) {
                System.err.printf("Can't read list of devices, error is %s", errbuf
                        .toString());
                return;
            }
 
            System.out.println("Network devices found:");
            int i = 0;
            for (PcapIf device : alldevs) {
                String description =
                        (device.getDescription() != null) ? device.getDescription()
                        : "No description available";
                System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
            }
            System.out.println("choose the one device from above list of devices");
            int ch = new Scanner(System.in).nextInt();
            PcapIf device = alldevs.get(ch);
 
            int snaplen = 64 * 1024;           // Capture all packets, no trucation
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
            int timeout = 10 * 1000;           // 10 seconds in millis
 
            //Open the selected device to capture packets
            Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
 
            if (pcap == null) {
                System.err.printf("Error while opening device for capture: "
                        + errbuf.toString());
                return;
            }
            System.out.println("device opened");
 
            //Create packet handler which will receive packets
            PcapPacketHandler jpacketHandler = new PcapPacketHandler() {
                Arp arp = new Arp();
 
                @Override
                public void nextPacket(PcapPacket packet, String user) {
                    //Here i am capturing the ARP packets only,you can capture any packet that you want by just changing the below if condition
                    if (packet.hasHeader(arp)) {
                        System.out.println("Hardware type" + arp.hardwareType());
                        System.out.println("Protocol type" + arp.protocolType());
                        System.out.println("Packet:" + arp.getPacket());
                        System.out.println();
                    }
                }
            };
            //we enter the loop and capture the 10 packets here.You can  capture any number of packets just by changing the first argument to pcap.loop() function below
            pcap.loop(10, jpacketHandler, "jnetpcap rocks!");
            //Close the pcap
            pcap.close();
        } catch (Exception ex) {
            System.out.println(ex);
        }
    }
}