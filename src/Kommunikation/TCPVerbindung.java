package Kommunikation;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
/**
 * Verbindugn
 * @author Dominik
 *
 */
public class TCPVerbindung implements Runnable{
	private Socket socket;
	private boolean ver, run;
	private ObjectInputStream in;
	private ObjectOutputStream out;
	private Controller controller;
	
	/**
	 * Konstruktor
	 * @param ip
	 * @param port
	 * @param c
	 * @throws UnknownHostException
	 * @throws IOException
	 */
	public TCPVerbindung(String ip, int port, Controller c) throws UnknownHostException, IOException{
		this(new Socket(ip, port),c);
	}
	/**
	 * Konstruktor
	 * @param socket
	 * @param c
	 * @throws IOException
	 */
	public TCPVerbindung(Socket socket, Controller c) throws IOException{
		this.socket = socket;
		this.controller = c;
		ver = false;
		this.open();
	}
	/**
	 * Oeffnet verbindung
	 * @throws IOException
	 */
	private void open() throws IOException{
		run=true;
		out = new ObjectOutputStream(socket.getOutputStream());
		in = new ObjectInputStream(socket.getInputStream());
		Thread t = new Thread(this);
		t.start();
		if(!this.controller.getServer()){
			this.controller.getLog().debug("Public-Key wird gesendet");
			this.send(this.controller.getPublicKey());
		}
	}
	/**
	 * Schließt Verbindung
	 */
	public void close(){
		run = false;
		if(in != null)
			try {
				in.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		if(out != null)
			try {
				out.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		if(socket != null)
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		
	}
	/**
	 * Gibt IP vom anderen ende zurueck
	 * @return
	 */
	public String getEndIP(){
		return socket.getInetAddress().getHostAddress();
	}
	/**
	 * Gibt IP zurueck
	 * @return
	 */
	public String getIP(){
		return socket.getLocalAddress().getHostAddress();
	}
	/**
	 * Sendet und verschluesselt nachrichten
	 * @param msg
	 */
	public void sendMessage(String msg){
		if(this.ver){
			try {
				Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
				aes.init(Cipher.ENCRYPT_MODE, this.controller.getKeyS());
				byte[] enc = aes.doFinal(msg.getBytes("UTF8"));
				sun.misc.BASE64Encoder base64encoder = new BASE64Encoder();
				String s = base64encoder.encode(enc);
				this.controller.getLog().info("Verschlüsselt: " + s);
				this.send(s);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}else{
			this.controller.getLog().info("Noch keine Sichere Ferbindung! \nSenden Fehlgeschlagen");
		}
	}
	/**
	 * sendet im Klartext
	 * @param msg
	 */
	public void sendPlainMessage(String msg){
		this.send("!Plain!:"+msg);
	}
	/**
	 * Sendet
	 * @param tosend
	 */
	public void send(Object tosend){
		try {
			out.writeObject(tosend);
			out.flush();
		} catch (IOException e) {
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
					e.printStackTrace();
				}
			}
		}catch(IOException e){
			if(!this.controller.getServer()){
				this.controller.getLog().error("Conection geschlossen");
				this.controller.shutdown();
			}else{
				this.controller.removeClient(this);
			}
		}
	}
	/**
	 * Verarbeitet input
	 * @param o
	 */
	private void handleIN(Object o){
		if(o instanceof PublicKey){
			try{
				PublicKey k = (PublicKey)o;
				Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				rsa.init(Cipher.ENCRYPT_MODE, k);
				SymetricK kk = new SymetricK(rsa.doFinal(this.controller.getKey().getEncoded()));
				this.send(kk);
				this.controller.getLog().info("Symetirc key gesendet!");
				this.ver = true;
			}catch(NoSuchAlgorithmException e){
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}
		}else if(o instanceof SymetricK){
			SymetricK k = (SymetricK)o;
			this.controller.extractKey(k.getK());
			this.ver = true;
		}else if(o instanceof String){
			String m = (String)o;
			if(m.startsWith("!Plain!:")){
				this.controller.getLog().info(m.replaceFirst("!Plain!:", ""));
				this.controller.sendPlainMessage(m.replaceFirst("!Plain!:", ""), this);
			}else{
				try {
					sun.misc.BASE64Decoder base64decoder = new BASE64Decoder();
					Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
					aes.init(Cipher.DECRYPT_MODE, this.controller.getKeyS());
					String msg = new String(aes.doFinal(base64decoder.decodeBuffer(m)));
					this.controller.getLog().info(msg);
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				} catch (NoSuchPaddingException e) {
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					e.printStackTrace();
				} catch (BadPaddingException e) {
					e.printStackTrace();
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
}
