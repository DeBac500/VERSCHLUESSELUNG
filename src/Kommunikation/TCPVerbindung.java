package Kommunikation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
			send(this.controller.getPublicKey().getEncoded());
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
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
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
				aes.init(Cipher.ENCRYPT_MODE, this.controller.getKey());
				this.send(aes.doFinal(msg.getBytes()));
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
			
		}
	}
	
	public void send(byte[] tosend){
		try {
			out.write(tosend);
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
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				byte buffer[] = new byte[1024];
				for(int s; (s=in.read(buffer)) > 0; )
				{
				  baos.write(buffer);
				  this.controller.getLog().debug("Nachricht erhalten");
				}
				handleIN(baos.toByteArray());
			}
		}catch(IOException e){
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	private void handleIN(byte[] in){
		this.controller.getLog().debug("Nachricht Erhalten1");
		if(this.controller.getServer() && !this.ver){
			try{
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				KeySpec keySpec = new X509EncodedKeySpec(in);
				PublicKey k = keyFactory.generatePublic(keySpec);
				Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				rsa.init(Cipher.ENCRYPT_MODE, k);
				send(rsa.doFinal(this.controller.getKey().getEncoded()));
				this.ver = true;
				this.controller.getLog().info("Verbindung nun Verschlüsselt!");
			}catch(NoSuchAlgorithmException e){
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
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
		}else 
			if(!this.controller.getServer() && !this.ver){
				SecretKeySpec key = new SecretKeySpec(in, "AES");
				this.controller.setKey(key);
				this.ver = true;
				this.controller.getLog().info("Verbindung nun Verschlüsselt!");
			}else
				if(this.ver){
					try {
						Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
						aes.init(Cipher.DECRYPT_MODE, this.controller.getKey());
						byte[] fin = aes.doFinal(in);
						String msg = new String(fin);
						this.controller.getLog().info(msg);
						this.controller.sendMessage(in, this);
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
				}
	}
}
