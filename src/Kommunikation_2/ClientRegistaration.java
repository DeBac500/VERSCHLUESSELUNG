package Kommunikation_2;

import java.io.IOException;
import java.net.ServerSocket;

public class ClientRegistaration implements Runnable{
	private Controller controller;
	private ServerSocket ssocket;
	private boolean run;
	
	public ClientRegistaration(int port, Controller c){
		try {
			this.controller = c;
			this.ssocket = new ServerSocket(port);
			this.run = true;
			Thread t = new Thread(this);
			t.start();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			c.shutdown();
		}
	}
	@Override
	public void run() {
		while (run){
			try{
				this.controller.addClient(this.ssocket.accept()); 
			}catch(IOException ioe){
				this.controller.getLog().error("Server accept error: \n" + ioe.getMessage());
			}
		}
	}
	public void stop(){
		this.run = false;
		if(ssocket != null)
			try {
				ssocket.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	}
}
