package com.example.ocean.engine;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
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

public class CertificateManager {

	private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000;

	private boolean revoked;		// Revocation status
	private String statusMessage;	// Details of revocation reason
	
	private X509Certificate rootCertificate;	//the current root certificate
	
	@SuppressWarnings("deprecation")
	public synchronized PKCS10CertificationRequest generateRequest(KeyPair pair) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		return new PKCS10CertificationRequest("SHA256withRSA",
											  new X500Principal("CN=Requested Test Certificate"),
											  pair.getPublic(),
											  null,
											  pair.getPrivate());
	}
	
	/**
	 * Take in a certification request, and issue a signed certificate
	 * 
	 * @param request
	 * @param rootPair
	 * @return
	 * @throws Exception
	 */
	public synchronized X509Certificate processRequest(PKCS10CertificationRequest request, KeyPair rootPair) throws Exception 
	{
		this.setRootCertificate(issueRootCert(rootPair));
		X509Certificate intermediateCert = issueCertificate(rootPair,request, this.rootCertificate);
		
		return intermediateCert;
	}
	
	/**
	 * Generate a self-signed V1 certificate to use as a CA root certificate
     * (Note that we are using deprecated methods here!)
	 * @param pair
	 * @return
	 * @throws Exception
	 */
	@SuppressWarnings("deprecation")
	public synchronized X509Certificate issueRootCert(KeyPair pair) throws Exception
	{
		X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();
		
		certGen.setSerialNumber(BigInteger.valueOf(1));
	    certGen.setIssuerDN(new X500Principal("CN=Test CA Certificate"));
	    certGen.setNotBefore(new Date(System.currentTimeMillis()));
	    certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
	    certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
	    certGen.setPublicKey(pair.getPublic());
	    certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
	
	    return certGen.generateX509Certificate(pair.getPrivate(), "BC");
	}
	
	/***
	 * Generate an X509 Certificate, based on a public key 
	 * and signed by another's private key.
	 * @param pubKey
	 * @param privKey
	 * @return
	 * @throws Exception
	 */
	@SuppressWarnings("deprecation")
	public synchronized X509Certificate issueRootCert(PublicKey pubKey, PrivateKey privKey) throws Exception
	{
		X509V1CertificateGenerator  certGen = new X509V1CertificateGenerator();
		
		certGen.setSerialNumber(BigInteger.valueOf(1));
	    certGen.setIssuerDN(new X500Principal("CN=Test CA Certificate"));
	    certGen.setNotBefore(new Date(System.currentTimeMillis()));
	    certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
	    certGen.setSubjectDN(new X500Principal("CN=Test Certificate"));
	    certGen.setPublicKey(pubKey);
	    certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
	
	    return certGen.generateX509Certificate(privKey, "BC");
	}
	
	/**
	 * Generate an intermediate v1 certificate, signed by a 3rd party.
	 * @param intKey
	 * @param caKey
	 * @param rootCert
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SecurityException
	 * @throws SignatureException
	 * @throws CertificateParsingException
	 * @throws NoSuchAlgorithmException 
	 * @throws IllegalArgumentException 
	 */
	@SuppressWarnings("deprecation")
	public synchronized X509Certificate issueCertificate(KeyPair rootPair,
														PKCS10CertificationRequest request,
														X509Certificate rootCert) throws	InvalidKeyException, 
																						NoSuchProviderException, 
																						SecurityException, 
																						SignatureException, 
																						CertificateParsingException, 
																						IllegalArgumentException, 
																						NoSuchAlgorithmException 			
	{										
		X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(rootCert.getSubjectX500Principal());
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
        certGen.setSubjectDN(new X500Principal("CN=TestCertificate"));
        certGen.setPublicKey(request.getPublicKey("BC"));
        certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
    
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(rootCert));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(request.getPublicKey("BC")));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

        return certGen.generateX509Certificate(rootPair.getPrivate(), "BC");
	}
	
	/**
	 * Take a certificate and convert to X500 private credential
	 * 
	 * @param caKey
	 * @param caCert
	 * @param alias
	 * @return
	 */
	public synchronized X500PrivateCredential toX500PrivateCredential(	PrivateKey caKey, 
																  		X509Certificate caCert,
																  		String alias)
	{
		return new X500PrivateCredential(caCert, caKey, alias);
	}
	
	/**
	 * Revoke a certificate chain via OCSP
	 * @param pubKey
	 * @param privKey
	 * @param caCert the root certificate
	 * @param revokedSerialNumber serial number of target certificate
	 * @param cert the intermediate certificate
	 * @return a BasicOSCPResp object
	 * @throws OCSPException
	 * @throws NoSuchProviderException
	 */
	@SuppressWarnings("deprecation")
	public synchronized BasicOCSPResp revokeCertificate(PublicKey pubKey,
											   PrivateKey privKey,
											   X509Certificate caCert,
											   BigInteger revokedSerialNumber,
											   X509Certificate cert) throws OCSPException, 
											   								NoSuchProviderException {

		CertificateID revokedID = new CertificateID(CertificateID.HASH_SHA1, caCert, revokedSerialNumber);

		OCSPReq request = OCSPServer.generateRequest(caCert, cert.getSerialNumber());		
		OCSPResp response = OCSPServer.generateResponse(request, privKey, pubKey, revokedID);
		
		BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
		
		return basicResponse;
	}

	//Getters and Setters for this class...
	
	public X509Certificate getRootCertificate() {
		return rootCertificate;
	}

	public void setRootCertificate(X509Certificate rootCertificate) {
		this.rootCertificate = rootCertificate;
	}
	
}
