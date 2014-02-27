package Kommunikation;

import java.util.Scanner;

/**
 * Verarbeitet Usereingaben
 * @author Dominik
 *
 */
public class UserInterface implements Runnable{
	private Controller controller;
	private boolean run,getpr, getsalt;
	private Scanner in;
	/**
	 * Konstruktor
	 * @param c
	 */
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
	/**
	 * Verarbeitet input
	 * @param msg
	 */
	public void handleIN(String msg){
		if(msg.startsWith("!plain")){
			String[] arg = msg.split(" ",2);
			if(arg.length == 2 ){
				this.controller.sendPlainMessage(arg[1]);
			}
		}else if(msg.startsWith("!end") || msg.startsWith("!exit")){
			this.controller.shutdown();
		}else if(this.getpr){
			this.controller.setpra(msg);
			this.getpr = false;
		}else if(this.getsalt){
			this.controller.setsalt(msg);
			this.getsalt = false;
		}else
			this.controller.sendMessage(msg);
	}
	/**
	 * Benaschrpucht salt
	 */
	public void getSalt(){
		this.getsalt = true;
	}
	/**
	 * Benaschrpucht pra
	 */
	public void getPra(){
		this.getpr = true;
	}
	/**
	 * Schliesst
	 */
	public void close(){
		this.run = false;
	}
}
