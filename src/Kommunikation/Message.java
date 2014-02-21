package Kommunikation;

import java.io.Serializable;

public class Message implements Serializable{
	private byte[] msg;
	private String type;

	public Message(byte[] msg, String type) {
		this.msg = msg;
		this.type = type;
	}

	public byte[] getMsg() {
		return msg;
	}

	public void setMsg(byte[] msg) {
		this.msg = msg;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
	
	
}
