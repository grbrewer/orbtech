package com.example.ocean.engine;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import java.math.BigInteger;

import java.util.Collection;
import java.util.Set;

import org.bouncycastle.ocsp.BasicOCSPResp;

public class PathChecker extends PKIXCertPathChecker {

	private KeyPair 		responderPair;
	private X509Certificate caCert;
	private BigInteger 		revokedSerialNumber;
	
	public PathChecker(	KeyPair responderPair,
						X509Certificate caCert,
						BigInteger revokedSerialNumber)
	{
		this.responderPair = responderPair;
		this.caCert = caCert;
		this.revokedSerialNumber = revokedSerialNumber;
	}
			
	
	@SuppressWarnings("rawtypes")
	@Override
	public void check(Certificate cert, Collection extensions)
			throws CertPathValidatorException {
		X509Certificate x509Cert = (X509Certificate) cert;
		
		try {
			
			
		}
		
		catch (Exception e)
		{
			throw new CertPathValidatorException(
					"exception verifying certificate: " + e, e);
		}
		
	}

	@Override
	public Set<String> getSupportedExtensions() 
	{
		return null;
	}

	@Override
	public void init(boolean arg0) throws CertPathValidatorException 
	{
		//ignore for now
	}

	@Override
	public boolean isForwardCheckingSupported() 
	{
		return true;
	}

}
