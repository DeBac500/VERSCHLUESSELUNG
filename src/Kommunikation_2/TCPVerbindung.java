package Kommunikation_2;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
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

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class TCPVerbindung implements Runnable{
	private Socket socket;
	private boolean ver, run;
	private ObjectInputStream in;
	private ObjectOutputStream out;
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
		out = new ObjectOutputStream(socket.getOutputStream());
		in = new ObjectInputStream(socket.getInputStream());
		Thread t = new Thread(this);
		t.start();
		if(!this.controller.getServer()){
			this.controller.getLog().debug("Send Public");
			//TODO send public key
			this.send(this.controller.getPublicKey());
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
				byte[] enc = aes.doFinal(msg.getBytes("UTF8"));
				sun.misc.BASE64Encoder base64encoder = new BASE64Encoder();
				String s = base64encoder.encode(enc);
				this.send(s);
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
			} catch (UnsupportedEncodingException e) {
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
				try {
					this.handleIN(in.readObject());
				} catch (ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}catch(IOException e){
			if(!this.controller.getServer()){
				this.controller.getLog().error("Conection Cloased");
				this.controller.shutdown();
			}else{
				this.controller.getLog().error("Client getrennt: "+ this.getEndIP());
				this.controller.removeClient(this);
			}
		}
	}
		
	private void handleIN(Object o){
		if(o instanceof PublicKey){
			try{
				PublicKey k = (PublicKey)o;
				Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				rsa.init(Cipher.ENCRYPT_MODE, k);
				SymetricK kk = new SymetricK(rsa.doFinal(this.controller.getKey().getEncoded()));
				this.send(kk);
				this.controller.getLog().info("Symetirc key gesendet!");
				//this.controller.getLog().debug(this.controller.getKeyS());
				this.ver = true;
			}catch(NoSuchAlgorithmException e){
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
		}else if(o instanceof SymetricK){
			SymetricK k = (SymetricK)o;
			this.controller.extractKey(k.getK());
			this.ver = true;
		}else if(o instanceof String){
			String m = (String)o;
			try {
				sun.misc.BASE64Decoder base64decoder = new BASE64Decoder();
				Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
				aes.init(Cipher.DECRYPT_MODE, this.controller.getKeyS());
				String msg = new String(aes.doFinal(base64decoder.decodeBuffer(m)));
				this.controller.getLog().info(msg);
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
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
