package com.example.ocean.engine;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.x509.*;
import org.bouncycastle.x509.extension.*;
import org.bouncycastle.ocsp.*;
import org.hibernate.Query;
import org.hibernate.Session;

import com.example.ocean.model.Keyring;

import javax.jws.WebService;

@WebService(endpointInterface = "com.example.ocean.engine.OceanInterface")
public class OceanImpl implements OceanInterface {
	
	private CryptoEngine crypteng;
	
	public OceanImpl() throws KeyStoreException, 
								   NoSuchAlgorithmException, 
								   CertificateException, 
								   IOException
	{
		crypteng = new CryptoEngine();
	}
	
	@Override
	public String[] getSerialNumbers(String username)
	{
		return crypteng.getPublicKeySerialNos(username);
	}
	
	@Override
	public String downloadPublicKey(String username, String serialNumber) throws NoSuchAlgorithmException, 
																				   NoSuchProviderException, 
																				   InvalidKeySpecException, 
																				   IOException
	{
		return crypteng.downloadPublicKey(username, serialNumber);
	}
	
	@Override
	public void publishPublicKey(String userEmail, String pkText) throws Exception
	{
		crypteng.publishPublicKey(userEmail, pkText);
	}
}
