package com.example.ocean.engine;

import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.ocsp.*;


@SuppressWarnings("deprecation")
public class OCSPServer {

	/**
	 * Generate an OSCP Request for a given Certificate (X509)
	 * @param issuerCert
	 * @param serialNumber
	 * @return
	 * @throws OCSPException
	 */
    @SuppressWarnings({ "rawtypes", "unchecked" })
	public static OCSPReq generateRequest(X509Certificate issuerCert, BigInteger serialNumber) 
        throws OCSPException
    {
        // Generate the id for the certificate we are looking for
        CertificateID   id = new CertificateID(CertificateID.HASH_SHA1, issuerCert, serialNumber);

        // basic request generation with nonce
        OCSPReqGenerator    gen = new OCSPReqGenerator();
        
        gen.addRequest(id);
        
        // create details for nonce extension
        // TODO generalise this code, and eliminate warnings
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        
        
        Vector     oids = new Vector();
        Vector     values = new Vector();
        
        oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
        
        
        gen.setRequestExtensions(new X509Extensions(oids, values));
        
        return gen.generate();
    }
    
    /**
     * Handle the OSCP response for Certificate validation / revocation
     * @param request
     * @param responderKey
     * @param pubKey
     * @param revokedID
     * @return
     * @throws NoSuchProviderException
     * @throws OCSPException
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
	public static OCSPResp generateResponse(OCSPReq request, PrivateKey responderKey, PublicKey pubKey, CertificateID revokedID) 
            throws NoSuchProviderException, OCSPException
    {
        BasicOCSPRespGenerator basicRespGen = new BasicOCSPRespGenerator(pubKey);
        
        X509Extensions reqExtensions = request.getRequestExtensions();
        
        if (reqExtensions != null)
        {
            X509Extension ext = reqExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        
            //TODO Generalise and expand the extensions code...
            
            if (ext != null)
            {
                Vector oids = new Vector();
                Vector values = new Vector();
                
                oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                values.add(ext);
                
                basicRespGen.setResponseExtensions(new X509Extensions(oids, values));
            }
           
        }
        
        //TODO improve on this crude array
        Req[] requests = request.getRequestList();
        
        for (int i = 0; i != requests.length; i++)
        {
            CertificateID certID = requests[i].getCertID();
            
            //TODO This requires generalisation as well..
            if (certID.equals(revokedID))
            {
                basicRespGen.addResponse(	certID, 
                							new RevokedStatus(new Date(), 
                							CRLReason.privilegeWithdrawn)	);
            }
            else
            {
                basicRespGen.addResponse(certID, CertificateStatus.GOOD);
            }
            
        }

        BasicOCSPResp basicResp = basicRespGen.generate("SHA256WithRSA", responderKey, null, new Date(), "BC");
        OCSPRespGenerator respGen = new OCSPRespGenerator();
        
        return respGen.generate(OCSPRespGenerator.SUCCESSFUL, basicResp);
    }
        
	
}
