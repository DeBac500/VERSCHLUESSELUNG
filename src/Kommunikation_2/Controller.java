package Kommunikation_2;

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
		log.info("Client starting ...");
		
		log.info("Generating Key....");
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		publicKey = keyPair.getPublic();
		privateKey = keyPair.getPrivate();
		log.info("Key generated!");
		
		
		this.clients = new ArrayList<TCPVerbindung>();
		try {
			this.clients.add(new TCPVerbindung(ip, port, this));
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			this.shutdown();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			this.shutdown();
		}
		
		this.ui = new UserInterface(this);
		this.log.info("Client started");
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
		log.info("Server starting ...");
		this.port = port;
		this.setUpServer();
	}
	public void setUpServer(){
		this.log.info("Please enter a passphrase:");
		this.ui.getPra();
	}
	public void setpra(String txt){
		this.passphrase = txt;
		this.log.info("Please enter Salt:");
		this.ui.getSalt();
	}
	public void setsalt(String txt){
		this.salt = txt;
		this.generatekey();
	}
	public void generatekey(){
		if((this.passphrase != null || this.passphrase != "") && (this.salt != null ||  this.salt != "")){
			try {
				log.info("Generating Key....");
				int iterations = 10000;
				SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
				tmp = factory.generateSecret(new PBEKeySpec(this.passphrase.toCharArray(), this.salt.getBytes(), iterations, 128));
				this.key = new SecretKeySpec(tmp.getEncoded(), "AES");
				log.info("Key generated!");
				this.server = new ClientRegistaration(port, this);
				this.clients = new ArrayList<TCPVerbindung>();
				this.log.info("Server started");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}else{
			this.log.info("Salt oder Passphrase sind nicht gesetzt bitte erneut versuchen!");
			this.setUpServer();
		}
	}
	public void initLogger(){
		PatternLayout layout = new PatternLayout( "%d{HH:mm:ss} %m%n" );
		ConsoleAppender consoleAppender = new ConsoleAppender( layout );
		log.addAppender(consoleAppender);
		log.setLevel(Level.ALL);
	}
	public boolean getServer(){return this.isServer;}
	public PublicKey getPublicKey(){ return this.publicKey;}
	public SecretKey getKey(){return this.tmp;}
	public SecretKeySpec getKeyS(){return this.key;}
	public void setKey(SecretKeySpec key){this.key = key;}
	public Logger getLog(){return this.log;}
	public void shutdown(){
		new Thread(new Runnable() {
			@Override
			public void run() {
				// TODO Auto-generated method stub
				if(Controller.this.server != null)
					Controller.this.server.stop();
				for(TCPVerbindung temp : Controller.this.clients){
					Controller.this.removeClient(temp);
				}
				if(ui != null)
					ui.close();
				System.exit(0);
			}
		});
		
	}
	public void addClient(Socket socket){
		try {
			this.clients.add(new TCPVerbindung(socket, this));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.log.info("Nerer Cleint Verbunden: " + socket.getInetAddress().getHostAddress());
	}
	public void removeClient(TCPVerbindung tcp){
		log.info("Client Disconected: " + tcp.getEndIP());
		tcp.close();
		this.clients.remove(tcp);
		
	}
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
	public void sendMessage(String msg){
		for(int i = 0; i < this.clients.size();i++){
			this.clients.get(i).sendMessage(msg);
		}
	}
	public void extractKey(byte[] msg){
		try {
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, this.privateKey);
			byte[] kb = rsa.doFinal(msg);
			this.key = new SecretKeySpec(kb, "AES");
			this.log.info("Symetric key recieved!");
			//this.log.debug(this.key);
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
	public static void main(String[] args){
		try {
			if(args.length > 0){
				if(args[0].equalsIgnoreCase("s")){
					new Controller(4444);
				}else if(args[0].equalsIgnoreCase("c")){
					new Controller("10.0.105.40",4444);
				}
			}else{
				System.out.println("Wrong arguments");
			}
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
