package Kommunikation_2;

import java.io.Serializable;

public class SymetricK implements Serializable{
	private byte[] k;
	public SymetricK(byte[] g){this.k = g;}
	public byte[] getK(){return this.k;};
}
