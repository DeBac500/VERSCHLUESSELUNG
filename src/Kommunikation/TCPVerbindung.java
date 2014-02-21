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
	private ObjectInputStream in;
	private ObjectOutputStream out;
	private Controller controller;
	
	
	public TCPVerbindung(String ip, int port, Controller c) throws UnknownHostException, IOException{
		this(new Socket(ip, port),c);
	}
	
	public TCPVerbindung(Socket socket, Controller c) throws IOException{
		this.socket = socket;
		this.controller = c;
		ver = false;
		this.open();
	}
	
	private void open() throws IOException{
		run=true;
		out = new ObjectOutputStream(socket.getOutputStream());
		in = new ObjectInputStream(socket.getInputStream());
		Thread t = new Thread(this);
		t.start();
		if(!this.controller.getServer()){
			this.controller.getLog().debug("Send Public");
			Message m = new Message(this.controller.getPublicKey().getEncoded(), "PKey");
			send(m);
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
			try {
				out.close();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
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
				Message m = new Message(aes.doFinal(msg.getBytes()),"Nachricht");
				this.send(m);
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
	
	public void send(Object tosend){
		try {
			out.writeObject(tosend);
			out.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Override
	public void run() {
		try{
			while(this.run){
				Object o = in.readObject();
				if(o instanceof Message)
					this.handleIN((Message)o);
				else
					this.controller.getLog().error("Konnte nicht zugewiesen werden!");
			}
		}catch(IOException e){
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private void handleIN(Message msg){
		this.controller.getLog().debug("Nachricht Erhalten2");
		
		if(msg.getType().equalsIgnoreCase("Nachricht") && this.ver)
			this.controller.sendMessage(msg, this);
			//this.controller.getLog().info("NeueNachricht");
		else{
			if(msg.getType().equalsIgnoreCase("PKey") && !this.ver && this.controller.getServer()){
				try {
					Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					KeySpec keySpec = new X509EncodedKeySpec(msg.getMsg());
					PublicKey keyFromBytes = keyFactory.generatePublic(keySpec);
					rsa.init(Cipher.ENCRYPT_MODE, keyFromBytes);
					Message m = new Message(rsa.doFinal(this.controller.getKey().getEncoded()), "Key");
					this.send(m);
					this.ver =true;
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
			}else
				if(msg.getType().equalsIgnoreCase("Key") && !this.ver && !this.controller.getServer()){
					this.controller.extractKey(msg);
					this.ver = true;
				}else
					this.controller.getLog().error("Nachricht konnte nicht zugeordnet werden!");
		}
	}
}
