package com.example.ocean.util;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;

public class CryptoUtil {

	/**
	 * Class definition for SHA1 randomization features
	 * @author gavin
	 *
	 */
	private static class FixedRand extends SecureRandom
	{
		MessageDigest	sha;
		byte[]			state;
		
		FixedRand()
		{
			try
			{
				this.sha = MessageDigest.getInstance("SHA1", "BC");
				this.state = sha.digest();
			}
			catch (Exception e)
			{
				throw new RuntimeException("can't find SHA-1!");
			}
		}
		
		public void nextBytes(byte[] bytes)
		{
			int off = 0;
			
			sha.update(state);
			
			while(off < bytes.length)
			{
				state = sha.digest();
				
				if (bytes.length - off > state.length) {
					System.arraycopy(state, 0, bytes, off, state.length);
				}
				
				else {
					System.arraycopy(state, 0, bytes, off, bytes.length-off);
				}
				
				off += state.length;
				
				sha.update(state);
			}
		}
		
	}
	
	/**
	 * Return a SecureRandom which produces the same value.
	 * <b>This is for testing only!</b>
	 * @return a fixed random
	 */
	public static SecureRandom createFixedRandom()
	{
		return new FixedRand();
	}
	
	public static SessionFactory buildHibernateSessionFactory()
	{
		//location of hibernate files : com/example/cryptotron/model/hibernate.cfg.xml
		
		try {
			return new Configuration().configure()
			.buildSessionFactory();
		} 
		catch (Throwable ex) {
			System.err.println("Initial SessionFactory creation failed." + ex);
			throw new ExceptionInInitializerError(ex);
		}
	}

		
	/**
	 * Extract a String from a given text file (UTF-8)
	 * 
	 * @param path
	 * @return
	 * @throws IOException
	 */
	
	public static String getTextFromFile(String path) throws IOException {
		
		File f = new File(path);
	    FileInputStream fin = new FileInputStream(f);
	    byte[] buffer = new byte[(int) f.length()];
	    new DataInputStream(fin).readFully(buffer);
	    fin.close();
	    
	    String text = new String(buffer, "UTF-8");
	
	    return text;
	}
	

	public static void saveToTextFile(String filename, byte[] text) throws IOException {

		FileOutputStream out = new FileOutputStream(filename + ".ctron");
		
		byte[] buffer = text;
		out.write(buffer, 0, buffer.length);
		
	}
	
	/**
	 * Generate a Hash of a given string input, for a given algorithm.
	 * @param stringInput
	 * @param algorithmName
	 * @return
	 * @throws java.security.NoSuchAlgorithmException
	 */
	public static String calculateSecurityHash(String stringInput, String algorithmName) throws java.security.NoSuchAlgorithmException 
	{
		String hexMessageEncode = "";
		byte[] buffer = stringInput.getBytes();
		java.security.MessageDigest messageDigest = java.security.MessageDigest.getInstance(algorithmName);
		
		messageDigest.update(buffer);
		
		byte[] messageDigestBytes = messageDigest.digest();
			
		for (int index=0; index < messageDigestBytes.length ; index ++) {
			
			int countEncode = messageDigestBytes[index] & 0xff;
			
			if (Integer.toHexString(countEncode).length() == 1)
				hexMessageEncode = hexMessageEncode + "0";
			
			hexMessageEncode = hexMessageEncode + Integer.toHexString(countEncode);
		}
		
		return hexMessageEncode;
	}
	
	/**
	 * Generates a serial number by combining Hash functions.
	 * @param publicKeyText
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String generateSerialNumber(String publicKeyText) throws NoSuchAlgorithmException 
	{
	
		String serialNumberEncoded = 	calculateSecurityHash(publicKeyText,"MD2") +  
										calculateSecurityHash(publicKeyText,"MD5") +
										calculateSecurityHash(publicKeyText,"SHA1");
		
		String serialNumber = ""
			    + serialNumberEncoded.charAt(32)
			    + serialNumberEncoded.charAt(76)
			    + serialNumberEncoded.charAt(100)
			    + serialNumberEncoded.charAt(50)
			    + "-"
			    + serialNumberEncoded.charAt(2)
			    + serialNumberEncoded.charAt(91)
			    + serialNumberEncoded.charAt(73)
			    + serialNumberEncoded.charAt(72)
			    + serialNumberEncoded.charAt(98)
			    + "-"
			    + serialNumberEncoded.charAt(47)
			    + serialNumberEncoded.charAt(65)
			    + serialNumberEncoded.charAt(18)
			    + serialNumberEncoded.charAt(85)
			    + "-"
			    + serialNumberEncoded.charAt(27)
			    + serialNumberEncoded.charAt(53)
			    + serialNumberEncoded.charAt(102)
			    + serialNumberEncoded.charAt(15)
			    + serialNumberEncoded.charAt(99); 
		
		return serialNumber;
	}
	
	/**
	 * Convert object to byte array
	 * @param obj
	 * @return
	 * @throws IOException
	 */
	public static byte[] convertToByteArray(Object obj) throws IOException {
	    
	    ByteArrayOutputStream bos = new ByteArrayOutputStream();
	    ObjectOutput out = new ObjectOutputStream(bos);   
	    out.writeObject(obj);
	    byte[] data = bos.toByteArray();
	    
	    return data;
	}
	
	
}
