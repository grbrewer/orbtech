package com.example.ocean.engine;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService
public interface OceanInterface {
	@WebMethod String[] getSerialNumbers(String username);
	@WebMethod String downloadPublicKey(String username, String serialNumber) throws	NoSuchAlgorithmException, 
																						NoSuchProviderException, 
																						InvalidKeySpecException, 
																						IOException;
	
	@WebMethod void publishPublicKey(String userEmail, String pkText) throws Exception;
																					
}
