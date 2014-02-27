package Sniffer;

import java.io.IOException;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
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
	private Logger log = Logger.getRootLogger();
	private ConsoleAppender con = new ConsoleAppender(new PatternLayout("%m%n"));

	public Sniffer(String sourFilter, String destFilter) {
		try {
			log.addAppender(new FileAppender(new PatternLayout("%m%n"), "Sniffer.log",true));
		} catch (IOException e) {
			System.err.println("Logger Problem!!");
		}
		log.addAppender(con);
		log.setLevel(Level.ALL);
		log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
				+"++++++++++++++++++++++++++++++++++NEW SESSION+++++++++++++++++++++++++++++++++++++\n"
				+ "with Filter Source: "+sourFilter+" Destination: "+destFilter);
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
		try {
			log.addAppender(new FileAppender(new PatternLayout("%m%n"), "Sniffer.log",true));
		} catch (IOException e) {
			System.err.println("Logger Problem!!");
		}
		log.addAppender(con);
		log.setLevel(Level.ALL);
		log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
				+"++++++++++++++++++++++++++++++++++NEW SESSION+++++++++++++++++++++++++++++++++++++\n"
				+ "with Filter Source: "+sourFilter+" Destination: "+destFilter+"\n");
		this.sourFilter = null;
		this.destFilter = null;
	}

	@Override
	public void nextPacket(PcapPacket packet, Object user) {
			if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {
				if(sourFilter==null){
					if(org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase(destFilter)){
						log.info("+----------------------------------TCP-PACKET-----------------------------------+\n"
								+ "Source-IP\n"+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source())+"\nDest-IP\n"
								+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination())+"\n\n");

								
						//System.out.println("Description: \n"+packet.getHeader(tcp));
						log.info("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
						log.info("\n");
					}
				}else if(destFilter==null){
					if(org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()).equalsIgnoreCase(sourFilter)){
						log.info("+----------------------------------TCP-PACKET-----------------------------------+\n"
								+ "Source-IP\n"+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source())+"\nDest-IP\n"
								+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination())+"\n\n");

								
						//System.out.println("Description: \n"+packet.getHeader(tcp));
						log.info("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
						log.info("\n");
					}
				}else
				if(org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase(sourFilter)&&
				   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()).equalsIgnoreCase(destFilter)){
					log.info("+----------------------------------TCP-PACKET-----------------------------------+\n"
							+ "Source-IP\n"+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source())+"\nDest-IP\n"
							+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination())+"\n\n");

							
					//System.out.println("Description: \n"+packet.getHeader(tcp));
					log.info("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
					log.info("\n");
				}
			}
		}
	}

