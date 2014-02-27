package Kommunikation_2;

import java.util.Scanner;


public class UserInterface implements Runnable{
	private Controller controller;
	private boolean run,getpr, getsalt;
	private Scanner in;
	
	public UserInterface(Controller c){
		this.controller = c;
		in = new Scanner(System.in);
		run = true;
		getpr = false;
		getsalt = false;
		Thread t = new Thread(this);
		t.start();
	}

	@Override
	public void run() {
		while(run){
			this.handleIN(in.nextLine());
		}
	}
	public void handleIN(String msg){
		if(msg.charAt(0) == '!'){
			String[] arg = msg.split(" ");
			if(arg[0].equalsIgnoreCase("!end") || arg[0].equalsIgnoreCase("!exit")){
				this.controller.shutdown();
			}
		}else if(this.getpr){
			this.controller.setpra(msg);
			this.getpr = false;
		}else if(this.getsalt){
			this.controller.setsalt(msg);
			this.getsalt = false;
		}else
			this.controller.sendMessage(msg);
	}
	public void getSalt(){
		this.getsalt = true;
	}
	public void getPra(){
		this.getpr = true;
	}
	
	public void close(){
		this.run = false;
	}
}
