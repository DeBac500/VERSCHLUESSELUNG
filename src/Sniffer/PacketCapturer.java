package Sniffer;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
 
public class PacketCapturer {
    public static void main(String[] args) {
        try {
            // Will be filled with NICs
            List<PcapIf> alldevs = new ArrayList();
 
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
            PcapIf device = (PcapIf) alldevs.get(ch);
 
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
            /**********************************************************************
    		 * Third we create a packet hander which will be dispatched to from the
    		 * libpcap loop.
    		 **********************************************************************/
    		PcapPacketHandler<Object> pph = new PcapPacketHandler<Object>() {
    			private Ip4 ip = new Ip4();
    			private Ip6 ip1 = new Ip6();
    			private Tcp tcp = new Tcp();

    			@Override
    			public void nextPacket(PcapPacket packet, Object user) {
    				// if (packet.hasHeader(eth)) {
    				// System.out.printf("ethernet.type=%X\n", eth.type());
    				// }

    				if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {
    					//if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase("10.0.105.40")) {
    						System.out.printf("+----------------------------------TCP-PACKET-----------------------------------+\n"+
    										  "Source-IP\n%s\nDest-IP\n%s\n",
    									      org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()),
    									      org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()));
    						
    						//System.out.println("Description: \n"+packet.getHeader(tcp));
    						System.out.println(org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
    						System.out.println();
    						// System.out.println(packet.toString());
    						// System.out.println(packet.getUTF8String(0, 1000));
    					//}
    				}
    			}
    		};
    		// PcapHandler<String> printSummaryHandler = new PcapHandler<String>() {
    		//
    		//
    		// public void nextPacket(String user, long seconds, int useconds,
    		// int caplen, int len, ByteBuffer buffer) {
    		// Date timestamp = new Date(seconds * 1000 + useconds / 1000); // In
    		// // millis
    		//
    		// System.out.printf(
    		// "Received packet at %s caplen=%-4d len=%-4d %s\n",
    		// timestamp.toString(), // timestamp to 1 ms accuracy
    		// caplen, // Length actually captured
    		// len, // Original length of the packet
    		// user // User supplied object
    		// );
    		// }
    		// };

    		/************************************************************
    		 * Fourth we enter the loop and tell it to capture 10 packets
    		 ************************************************************/
    		pcap.loop(Integer.MAX_VALUE, pph, "jNetPcap rocks!");

    		/*
    		 * Last thing to do is close the pcap handle
    		 */
    		pcap.close();
        } catch (Exception ex) {
            System.out.println(ex);
        }
    }
}