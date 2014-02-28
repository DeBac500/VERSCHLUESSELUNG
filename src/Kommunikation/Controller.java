package Kommunikation;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

public class Controller {
	private Logger log = Logger.getRootLogger();
	private boolean isServer;
	private SecretKeySpec key;
	private SecretKey tmp;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private ArrayList<TCPVerbindung> clients;
	private ClientRegistaration server;
	private UserInterface ui;
	
	private String passphrase,salt;
	private int port;
	/**
	 * Konstruktor fuer Client
	 * @param ip
	 * @param port
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws UnknownHostException 
	 * @throws InvalidKeySpecException 
	 */
	public Controller(String ip, int port) throws NoSuchAlgorithmException{
		initLogger();
		this.isServer = false;
		log.info("Client startet ...");
		
		log.info("Key wird generiert....");
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();
		log.info("Key wurde generiert!");
		
		
		this.clients = new ArrayList<TCPVerbindung>();
		try {
			this.clients.add(new TCPVerbindung(ip, port, this));
			
		} catch (UnknownHostException e) {
			e.printStackTrace();
			this.shutdown();
		} catch (IOException e) {
			e.printStackTrace();
			this.shutdown();
		}
		
		this.ui = new UserInterface(this);
		this.log.info("Client gestarted!");
	}
	/**
	 * Konstruktor fuer Server
	 * @param port
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public Controller(int port) throws NoSuchAlgorithmException, InvalidKeySpecException{
		initLogger();
		this.isServer=true;
		this.ui = new UserInterface(this);
		log.info("Server startet ...");
		this.port = port;
		this.setUpServer();
	}
	/**
	 * Startet Server
	 */
	public void setUpServer(){
		this.log.info("Please enter a passphrase:");
		this.ui.getPra();
	}
	/**
	 * sezt Para
	 * @param txt
	 */
	public void setpra(String txt){
		this.passphrase = txt;
		this.log.info("Please enter Salt:");
		this.ui.getSalt();
	}
	/**
	 * sezt Salt
	 * @param txt
	 */
	public void setsalt(String txt){
		this.salt = txt;
		this.generatekey();
	}
	/**
	 * Generiert Symetrischen Key
	 */
	public void generatekey(){
		if((this.passphrase != null || this.passphrase != "") && (this.salt != null ||  this.salt != "")){
			try {
				log.info("Key wird generiert....");
				int iterations = 10000;
				SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
				tmp = factory.generateSecret(new PBEKeySpec(this.passphrase.toCharArray(), this.salt.getBytes(), iterations, 128));
				this.key = new SecretKeySpec(tmp.getEncoded(), "AES");
				log.info("Key wurde generiert!");
				this.server = new ClientRegistaration(port, this);
				this.clients = new ArrayList<TCPVerbindung>();
				this.log.info("Server gestarted!");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				e.printStackTrace();
			}
		}else{
			this.log.info("Salt oder Passphrase sind nicht gesetzt bitte erneut versuchen!");
			this.setUpServer();
		}
	}
	/**
	 * Startet Logger
	 */
	public void initLogger(){
		PatternLayout layout = new PatternLayout( "%d{HH:mm:ss} %m%n" );
		ConsoleAppender consoleAppender = new ConsoleAppender( layout );
		log.addAppender(consoleAppender);
		log.setLevel(Level.ALL);
	}
	/**
	 * gibt an ob es ein Server ist der nicht
	 * @return
	 */
	public boolean getServer(){return this.isServer;}
	/**
	 * gibt publicKey zurück
	 * @return
	 */
	public PublicKey getPublicKey(){ return this.publicKey;}
	/**
	 * gibt Symetrischen key zurück
	 * @return
	 */
	public SecretKey getKey(){return this.tmp;}
	/**
	 * gibt Symetrischen key zurück
	 * @return
	 */
	public SecretKeySpec getKeyS(){return this.key;}
	/**
	 * Setzt key
	 * @param key
	 */
	public void setKey(SecretKeySpec key){this.key = key;}
	/**
	 * ibt Logger zurück
	 * @return
	 */
	public Logger getLog(){return this.log;}
	/**
	 * Beendet das Programm
	 */
	public void shutdown(){
		new Thread(new Runnable() {
			@Override
			public void run() {
				if(Controller.this.server != null)
					Controller.this.server.stop();
				for(TCPVerbindung temp : Controller.this.clients){
					Controller.this.removeClient(temp);
				}
				if(ui != null)
					ui.close();
				System.exit(0);
			}
		}).start();;
	}
	/**
	 * Fügt Clinet hinzu
	 * @param socket
	 */
	public void addClient(Socket socket){
		try {
			this.clients.add(new TCPVerbindung(socket, this));
		} catch (IOException e) {
			e.printStackTrace();
		}
		this.log.info("Neuer Cleint Verbunden: " + socket.getInetAddress().getHostAddress());
	}
	/**
	 * Löscht Client
	 * @param tcp
	 */
	public void removeClient(TCPVerbindung tcp){
		log.info("Client getrennt: " + tcp.getEndIP());
		tcp.close();
		this.clients.remove(tcp);
		
	}
	/**
	 * Sendet Messages
	 * @param msg
	 * @param tcp
	 */
	public void sendMessage(String msg, TCPVerbindung tcp){
		try {
			Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
			aes.init(Cipher.DECRYPT_MODE, this.key);
			this.log.info(new String(aes.doFinal(msg.getBytes())));
			for(int i = 0; i < this.clients.size();i++){
				if(tcp != null){
					if(!this.clients.get(i).equals(tcp)){
						this.clients.get(i).send(msg);
					}
				}else{
					this.clients.get(i).send(msg);
				}
			}
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
		}
	}
	/**
	 * Sendet Messegaes
	 * @param msg
	 */
	public void sendMessage(String msg){
		for(int i = 0; i < this.clients.size();i++){
			this.clients.get(i).sendMessage(msg);
		}
	}
	/**
	 * Sendet im Klartext
	 * @param msg
	 */
	public void sendPlainMessage(String msg){
		for(int i = 0; i < this.clients.size();i++){
			this.clients.get(i).sendPlainMessage(msg);
		}
	}
	/**
	 * Sendet im Klartext
	 * @param msg
	 */
	public void sendPlainMessage(String msg,TCPVerbindung tcp){
		for(int i = 0; i < this.clients.size();i++){
			if(!this.clients.get(i).equals(tcp))
				this.clients.get(i).sendPlainMessage(msg);
		}
	}
	/**
	 * 
	 * @param msg
	 */
	public void extractKey(byte[] msg){
		try {
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, this.privateKey);
			byte[] kb = rsa.doFinal(msg);
			this.key = new SecretKeySpec(kb, "AES");
			this.log.info("Symetric key empfangen!");
			//this.log.debug(this.key);
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
		}
	}
	/**
	 * Main methode
	 * @param args
	 */
	public static void main(String[] args){
		try {
			if(args.length > 0){
				if(args[0].equalsIgnoreCase("sd")){
					new Controller(4444);
				}else if(args[0].equalsIgnoreCase("cd")){
					new Controller("127.0.0.1",4444);
				}else if(args[0].equalsIgnoreCase("s")){
					if(args.length == 2)
						new Controller(Integer.parseInt(args[1]));
					else{
						System.out.println("Wrong arguments");
						System.out.println("<ds>");
						System.out.println("<dc>");
						System.out.println("<s> <port>");
						System.out.println("<c> <IP> <port>");
					}
				}else if(args[0].equalsIgnoreCase("c")){
					if(args.length == 3)
						new Controller(args[1], Integer.parseInt(args[2]));
					else{
						System.out.println("Wrong arguments");
						System.out.println("<ds>");
						System.out.println("<dc>");
						System.out.println("<s> <port>");
						System.out.println("<c> <IP> <port>");
					}
				}
			}else{
				System.out.println("Wrong arguments");
				System.out.println("<ds>");
				System.out.println("<dc>");
				System.out.println("<s> <port>");
				System.out.println("<c> <IP> <port>");
			}
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		} catch(NumberFormatException e){
			System.err.println("Bitte den Port als Zahl angeben!");
			System.exit(0);
		}
	}
}
