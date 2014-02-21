package Kommunikation;

import java.util.Scanner;


public class UserInterface implements Runnable{
	private Controller controller;
	private boolean run;
	private Scanner in;
	
	public UserInterface(Controller c){
		this.controller = c;
		in = new Scanner(System.in);
		run = true;
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
		}else
			this.controller.sendMessage(msg);
	}
	
	public void close(){
		this.run = false;
	}
}
