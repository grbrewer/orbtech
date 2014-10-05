package com.example.ocean.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.example.ocean.engine.*;

public class TestEngine {

	private CryptoEngine cryptEng;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
		cryptEng = new CryptoEngine();
		//cryptEng.generateKeyPair();
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testDownloadPublicKey() throws NoSuchAlgorithmException, 
												 NoSuchProviderException, 
												 InvalidKeySpecException, 
												 IOException {
		
		byte[] publicKey = cryptEng.downloadPublicKey("flynn@encom.com", "fff5-1c990-ccd1-67a48");
		assertNotNull(publicKey);
	}

	@Test
	public void testGetPublicKeySerialNos() {
		String[] serialNos = cryptEng.getPublicKeySerialNos("jon@doe.org");
		System.out.println(serialNos[0]);
		assertNotNull(serialNos);
	}

}
