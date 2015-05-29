package com.example.ocean.engine;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.xml.ws.Endpoint;

public class OceanWSPublisher {
	
	public static void main(String[] args) throws 	KeyStoreException, 
														NoSuchAlgorithmException, 
														CertificateException, 
														IOException 
	{  
		Endpoint.publish("http://192.168.0.4:8080/WS/Ocean", new OceanImpl());  
	}  	
}
