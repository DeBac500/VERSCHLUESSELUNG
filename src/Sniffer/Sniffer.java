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

/**
 * Sniffer der auschließlich TCP-Pakete mitsnifft. In dieser Version gibt er Source- und Destination-IP, sowie die Payload des
 * Paketes aus. Zusätzlich ist es möglich Filter in Form von Source-IP und Destination-IP oder nur eines von beiden
 * anzugeben. Zusätzlich wird der gesamte Trace in einem File mitgeschrieben.
 * @author Alexander Rieppel
 *
 */
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
		log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
				+"++++++++++++++++++++++++++++++++++NEW SESSION+++++++++++++++++++++++++++++++++++\n");
				log.info("with Filter Source: "+sourFilter+" Destination: "+destFilter+"\n");
				
		this.sourFilter = sourFilter;
		this.destFilter = destFilter;
	}

	public Sniffer() {
		try {
			log.addAppender(new FileAppender(new PatternLayout("%m%n"), "Sniffer.log",true));
		} catch (IOException e) {
			System.err.println("Logger Problem!!");
		}
		log.addAppender(con);
		log.setLevel(Level.ALL);
		log.info("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
				+"++++++++++++++++++++++++++++++++++NEW SESSION+++++++++++++++++++++++++++++++++++\n"
				+ "with Filter none \n");
		this.sourFilter = null;
		this.destFilter = null;
	}

	
	@Override
	/**
	 * Methode welche sich jeweils immer ein Paket nimmt und es analysiert.
	 */
	public void nextPacket(PcapPacket packet, Object user) {
			if (packet.hasHeader(tcp) && packet.hasHeader(ip)) {
				if(sourFilter==null&&destFilter!=null){
					if(org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()).equalsIgnoreCase(destFilter)){
						log.info("+----------------------------------TCP-PACKET----------------------------------+\n"
								+ "Source-IP\n"+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source())+"\nDest-IP\n"
								+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination())+"\n\n");

								
						//System.out.println("Description: \n"+packet.getHeader(tcp));
						log.info("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
						log.info("\n");
					}
				}else if(destFilter==null&&sourFilter!=null){
					if(org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase(sourFilter)){
						log.info("+----------------------------------TCP-PACKET----------------------------------+\n"
								+ "Source-IP\n"+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source())+"\nDest-IP\n"
								+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination())+"\n\n");

								
						//System.out.println("Description: \n"+packet.getHeader(tcp));
						log.info("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
						log.info("\n");
					}
				}else if(sourFilter==null&&destFilter==null){
					log.info("+----------------------------------TCP-PACKET----------------------------------+\n"
							+ "Source-IP\n"+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source())+"\nDest-IP\n"
							+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination())+"\n\n");

							
					//System.out.println("Description: \n"+packet.getHeader(tcp));
					log.info("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
					log.info("\n");
				}else if(sourFilter.equals("all")&&destFilter!=null){
					if(sourFilter!=null&&destFilter!=null&&org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase(destFilter)||
							   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()).equalsIgnoreCase(destFilter)){
					log.info("+----------------------------------TCP-PACKET----------------------------------+\n"
							+ "Source-IP\n"+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source())+"\nDest-IP\n"
							+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination())+"\n\n");

							
					//System.out.println("Description: \n"+packet.getHeader(tcp));
					log.info("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
					log.info("\n");
					}
				}else if(sourFilter!=null&&destFilter!=null&&org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source()).equalsIgnoreCase(sourFilter)&&
				   org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination()).equalsIgnoreCase(destFilter)){
					log.info("+----------------------------------TCP-PACKET----------------------------------+\n"
							+ "Source-IP\n"+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).source())+"\nDest-IP\n"
							+org.jnetpcap.packet.format.FormatUtils.ip(packet.getHeader(ip).destination())+"\n\n");

							
					//System.out.println("Description: \n"+packet.getHeader(tcp));
					log.info("PAYLOAD\n"+ org.jnetpcap.packet.format.FormatUtils.hexdump(packet.getHeader(tcp).getPayload()));
					log.info("\n");
				}
			}
		}
	}

