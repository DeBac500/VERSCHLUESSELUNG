package Kommunikation;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class TCPVerbindung implements Runnable{
	private Socket socket;
	private boolean ver, run;
	private BufferedReader in;
	private PrintWriter out;
	private Controller controller;
	private String empf;
	
	
	public TCPVerbindung(String ip, int port, Controller c) throws UnknownHostException, IOException{
		this(new Socket(ip, port),c);
	}
	
	public TCPVerbindung(Socket socket, Controller c) throws IOException{
		empf = "";
		this.socket = socket;
		this.controller = c;
		ver = false;
		this.open();
	}
	
	private void open() throws IOException{
		run=true;
		out = new PrintWriter(socket.getOutputStream());
		in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		Thread t = new Thread(this);
		t.start();
		if(!this.controller.getServer()){
			this.controller.getLog().debug("Send Public");
			//TODO send public key
			String s = new String(this.controller.getPublicKey().getEncoded());
			this.controller.getLog().info(s);
			this.send(s);
		}
	}
	public void close(){
		run = false;
		if(in != null)
			try {
				in.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		if(out != null)
			out.close();
		if(socket != null)
			try {
				socket.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
	}
	
	public String getEndIP(){
		return socket.getInetAddress().getHostAddress();
	}
	public String getIP(){
		return socket.getLocalAddress().getHostAddress();
	}
	
	public void sendMessage(String msg){
		if(this.ver){
			try {
				Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
				aes.init(Cipher.ENCRYPT_MODE, this.controller.getKeyS());
				this.send(new String(aes.doFinal(msg.getBytes())));
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}else{
			this.controller.getLog().info("Noch keine Sichere Ferbindung! \nSenden Fehlgeschlagen");
		}
	}
	
	public void send(String tosend){
		out.print(tosend);
		out.flush();
	}
	
	@Override
	public void run() {
		try{
			while(this.run){
				if(in.ready()){
					char[] input = new char[1024];
					String txt = "";
					while(in.ready()){
						in.read(input);
						System.out.println("TEST");
						txt += String.valueOf(input);
						input = new char[1024];
					}
					handleIN(txt);
				}
			}
		}catch(IOException e){
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
		
	private void handleIN(String msg){
		this.controller.getLog().debug("Nachricht Erhalten:");
		this.controller.getLog().debug(msg + "\n");
		if(!this.ver && this.controller.getServer()){
			try {
				Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				PublicKey publicKey = 
					    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(msg.getBytes()));
				rsa.init(Cipher.ENCRYPT_MODE, publicKey);
				this.send(new String(rsa.doFinal(this.controller.getKey().getEncoded())));
				this.controller.getLog().info("send Symetric key!");
				this.ver = true;
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}else if(!this.ver && !this.controller.getServer()){
			this.controller.extractKey(msg);
			this.ver = true;
		}else if(this.ver){
			this.controller.sendMessage(msg, this);
		}else{
			this.controller.getLog().error("Nachricht konnte nicht zugeordnet werden!");
		}
	}
}
