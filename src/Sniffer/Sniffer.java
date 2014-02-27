package Sniffer;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Sniffer implements PcapPacketHandler {
	private Ip4 ip = new Ip4();
	private Ip6 ip1 = new Ip6();
	private Tcp tcp = new Tcp();
	private String sourFilter;
	private String destFilter;

	public Sniffer(String sourFilter, String destFilter) {
		if((sourFilter!=null||sourFilter!="")&&(destFilter!=null||destFilter!="")){
			this.sourFilter = sourFilter;
			this.destFilter = destFilter;
			if(this.sourFilter=="s"){
				sourFilter=destFilter;
				destFilter=null;
			}else if(this.sourFilter=="d"){
				sourFilter=null;
			}
		}else{
			this.sourFilter = null;
			this.destFilter = null;
		}
	}

	public Sniffer() {
		this.sourFilter = null;
		this.destFilter = null;
	}

	@Override
	public void nextPacket(PcapPacket packet, Object user) {
			if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {
				if(sourFilter==null){
					if(org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase(destFilter)){
						System.out.printf("+----------------------------------TCP-PACKET-----------------------------------+\n"
										   + "Source-IP\n%s\nDest-IP\n%s\n\n",
										   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()),
										   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()));

								
						//System.out.println("Description: \n"+packet.getHeader(tcp));
						System.out.println("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
						System.out.println();
					}
				}else if(destFilter==null){
					if(org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()).equalsIgnoreCase(sourFilter)){
						System.out.printf("+----------------------------------TCP-PACKET-----------------------------------+\n"
										   + "Source-IP\n%s\nDest-IP\n%s\n\n",
										   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()),
										   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()));

								
						//System.out.println("Description: \n"+packet.getHeader(tcp));
						System.out.println("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
						System.out.println();
					}
				}else
				if(org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase(sourFilter)&&
				   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()).equalsIgnoreCase(destFilter)){
					System.out.printf("+----------------------------------TCP-PACKET-----------------------------------+\n"
							   + "Source-IP\n%s\nDest-IP\n%s\n\n",
							   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()),
							   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()));

					
					//System.out.println("Description: \n"+packet.getHeader(tcp));
					System.out.println("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
					System.out.println();
				}
			}
		}
	}

