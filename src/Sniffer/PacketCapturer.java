package Sniffer;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
/**
 * Klasse beinhaltet die Hauptklasse die einen Sniffer vorbereitet.
 * @author Alexander Rieppel
 */
public class PacketCapturer {
	private static Pcap pcap;
    public static void main(String[] args) {
    	new Thread(new Runnable() {
			private Scanner in = new Scanner(System.in);
			@Override
			public void run() {
				while(true)
					handle(in.nextLine());
			}
			public void handle(String msg){
				//Closing the Handler
	    		pcap.close();
				System.exit(0);
			}
		}).start();
        try {
        	double chooser=0;
        	if(args.length == 2&&args[0].equals("s")){
        		args[0]=args[1];
        		args[1]=null;
            	chooser=1;
            }else if(args.length == 2&&args[0].equals("d")){
            	chooser=1;
            	args[0]=null;
            }else{
            	System.err.println("Argumente entsprechen nicht den Richtlinien! Automatische Fortsetzung ohne Argumente!");
            	chooser=0;
            }
            if(args.length==3&&args[0].equals("sd")){
            	chooser=2;
            }
            if(args.length==0){
            	chooser=0;
            }
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
            System.out.println("choose one device from the list above");
            int ch = new Scanner(System.in).nextInt();
            PcapIf device = (PcapIf) alldevs.get(ch);
 
            int snaplen = 64 * 1024;           // Capture all packets, no trucation
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
            int timeout = 10 * 1000;           // 10 seconds in millis
 
            //Open the selected device to capture packets
            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
 
            if (pcap == null) {
                System.err.printf("Error while opening device for capture: "
                        + errbuf.toString());
                return;
            }
            System.out.println("device opened");
 
            //Create packet handler which will receive packets
            Sniffer sniff;
            if(chooser==0){
            	sniff = new Sniffer();
            	pcap.loop(Integer.MAX_VALUE, sniff, "FINISHED!");
            }
            if(chooser==1){
            	sniff = new Sniffer (args[0],args[1]);
            	pcap.loop(Integer.MAX_VALUE, sniff, "FINISHED!");
            }
            if(chooser==2){
            	sniff = new Sniffer(args[1],args[2]);
            	//Loop to continue capturing
            	pcap.loop(Integer.MAX_VALUE, sniff, "FINISHED!");
            }
            
    		
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
    }
}