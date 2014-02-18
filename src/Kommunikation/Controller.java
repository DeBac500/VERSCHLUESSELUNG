package Kommunikation;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

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
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private ArrayList<TCPVerbindung> clients;
	private ClientRegistaration server;
	private UserInterface ui;
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
		log.info("Server starting ...");
		
		log.info("Generating Key....");
		String passphrase = "ajKSHDJKSAdoeljksaDKLSCLAHeolsjkvdvnaueiodnvspnffdfbnasueodjfUENLUEBKNOEJJN";
		byte[] salt = "VERSCHLUESSELUNG_5AHITT_VSDBHUE".getBytes();
		int iterations = 10000;
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		SecretKey tmp = factory.generateSecret(new PBEKeySpec(passphrase.toCharArray(), salt, iterations, 128));
		this.key = new SecretKeySpec(tmp.getEncoded(), "AES");
		log.info("Key generated!");
		
		this.server = new ClientRegistaration(port, this);
		this.clients = new ArrayList<TCPVerbindung>();
		this.ui = new UserInterface(this);
		this.log.info("Server started");
	}
	public void initLogger(){
		PatternLayout layout = new PatternLayout( "%d{HH:mm:ss} %m%n" );
		ConsoleAppender consoleAppender = new ConsoleAppender( layout );
		log.addAppender(consoleAppender);
		log.setLevel(Level.ALL);
	}
	public boolean getServer(){return this.isServer;}
	public PublicKey getPublicKey(){ return this.publicKey;}
	public SecretKeySpec getKey(){return this.key;}
	public void setKey(SecretKeySpec key){this.key = key;}
	public Logger getLog(){return this.log;}
	public void shutdown(){
		if(this.server != null)
			this.server.stop();
		for(TCPVerbindung temp : this.clients){
			this.removeClient(temp);
		}
		if(ui != null)
			ui.close();
		System.exit(0);
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
		for(int i = 0; i < this.clients.size();i++){
			if(tcp != null){
				if(this.clients.get(i).equals(tcp)){
					this.clients.get(i).sendMessage(msg);
				}
			}else{
				this.clients.get(i).sendMessage(msg);
			}
		}
	}
	public void sendMessage(byte[] msg, TCPVerbindung tcp){
		for(int i = 0; i < this.clients.size();i++){
			if(tcp != null){
				if(this.clients.get(i).equals(tcp)){
					this.clients.get(i).send(msg);
				}
			}else{
				this.clients.get(i).send(msg);
			}
		}
	}
	public static void main(String[] args){
		try {
			if(args.length > 0){
				if(args[0].equalsIgnoreCase("s")){
					new Controller(4444);
				}else if(args[0].equalsIgnoreCase("c")){
					new Controller("127.0.0.1",4444);
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
