package Kommunikation;

import java.io.Serializable;
/**
 * Speicert Key
 * @author Dominik
 *
 */
public class SymetricK implements Serializable{
	private byte[] k;
	public SymetricK(byte[] g){this.k = g;}
	public byte[] getK(){return this.k;};
	public void setK(byte[] k){this.k = k;}
}
