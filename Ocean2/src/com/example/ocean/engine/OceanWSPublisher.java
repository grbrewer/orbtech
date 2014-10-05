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
		Endpoint.publish("http://localhost:8080/WS/Ocean", new OceanImpl());  
	}  	
}
