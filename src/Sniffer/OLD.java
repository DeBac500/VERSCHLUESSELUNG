package Sniffer;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Queue;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;

/**
 * This example is the classic libpcap example shown in nearly every tutorial on
 * libpcap. It gets a list of network devices, presents a simple ASCII based
 * menu and waits for user to select one of those interfaces. We will just
 * select the first interface in the list instead of taking input to shorten the
 * example. Then it opens that interface for live capture. Using a packet
 * handler it goes into a loop to catch a few packets, say 10. Prints some
 * simple info about the packets, and then closes the pcap handle and exits.
 * 
 * @author Mark Bednarczyk
 * @author Sly Technologies, Inc.
 */
public class OLD {

	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with
														// NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/********************************************
		 * First get a list of devices on this system
		 ********************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
		for (PcapIf device : alldevs) {
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
					device.getDescription());
		}

		PcapIf device = alldevs.get(2); // We know we have atleast 1 device
		System.out.printf("\nChoosing '%s' on your behalf:\n",
				device.getDescription());

		/***************************************
		 * Second we open up the selected device
		 ***************************************/
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000; // 10 seconds in millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout,
				errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
					+ errbuf.toString());
			return;
		}

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
					if (org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase("10.0.105.40")) {
						System.out.println("Source-IP: "+ org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()));
						System.out.println("Dest-IP: "+ org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()));
						System.out.println("Payload: "+ org.jnetpcap.packet.format.FormatUtils.asString((packet.getHeader(tcp).getPayload())));
						System.out.println();
						// System.out.println(packet.toString());
						// System.out.println(packet.getUTF8String(0, 1000));
					}
				}
			}

			public void processIp4(Ip4 ip) {
				System.out.println(ip.toString());
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
	}

}