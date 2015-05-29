package com.example.ocean.engine;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.Signature;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500PrivateCredential;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PEMParser;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import com.example.ocean.model.*;
import com.example.ocean.util.*;

public class CryptoEngine {

	public static String ROOT_ALIAS = "root";
	public static String INTERMEDIATE_ALIAS = "intermediate";
	
	private User currentUser;
	private Keyring	 currentKeyRing;
	private Certificate currentRootCert;	
	
	private String currentUserPassword;

	private KeyStore privateKeyStore;
	
	private SessionFactory hibernateSessionFactory;
	
	private CertificateManager certificateManager;
	
	private ArrayList<Certificate> certificateCache;
	private ArrayList<Keyring> publicKeyCache;

	//Getters and Setters for cache data
	
	public ArrayList<Certificate> getCertificateCache() {
		return certificateCache;
	}

	public void setCertificateCache(ArrayList<Certificate> certificateCache) {
		this.certificateCache = certificateCache;
	}

	public ArrayList<Keyring> getPublicKeyCache() {
		return publicKeyCache;
	}

	public void setPublicKeyCache(ArrayList<Keyring> publicKeyCache) {
		this.publicKeyCache = publicKeyCache;
	}

	//Getters and setters for private data
	
	public User getCurrentUser() {
		return currentUser;
	}

	public void setCurrentUser(User currentUser) {
		this.currentUser = currentUser;
	}

	public Keyring getCurrentKeyRing() {
		return currentKeyRing;
	}

	public void setCurrentKeyRing(Keyring currentKeyRing) {
		this.currentKeyRing = currentKeyRing;
	}

	public KeyStore getPrivateKeyStore() {
		return privateKeyStore;
	}

	public void setPrivateKeyStore(KeyStore privateKeyStore) {
		this.privateKeyStore = privateKeyStore;
	}

	//---------------- Class constructor ----------------- //
	
	public CryptoEngine() throws	KeyStoreException, 
									NoSuchAlgorithmException, 
									IOException, 
									CertificateException { 
		
		hibernateSessionFactory = CryptoUtil.buildHibernateSessionFactory();
		
		//Initialise Certificate Manager
		certificateManager = new CertificateManager();
		
		currentUser = new User("kevin@encom.com", "90210", "GL12AS");
		currentUserPassword = "reindeer2048";
		
		currentKeyRing = new Keyring();
		currentRootCert = new Certificate();
		
		privateKeyStore = KeyStore.getInstance("JKS");
		
		privateKeyStore.load(null, null);
		
		//Initialise our repositories of certificates and public keys
		certificateCache = new ArrayList<Certificate>();
		publicKeyCache = new ArrayList<Keyring>();
		
		//Download our public keys from database
		publicKeyCache = downloadPublicKeys(currentUser.getEmail());
		
	}
	
	//-----------------Some Utility Functions --------------------//
	/**
	 * Reconstruct Public Key from X509EncodedKeySpec
	 * @param pubKeyData
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 */
	public static PublicKey stringToPublicKey(String pubKeyData) throws IOException, 
																		NoSuchAlgorithmException, 
																		NoSuchProviderException, 
																		InvalidKeySpecException 
	{
		StringReader reader = new StringReader(pubKeyData);
		
		PEMParser keyReader = new PEMParser(reader);
		SubjectPublicKeyInfo pubKeyInfo = (SubjectPublicKeyInfo) keyReader.readObject();
		
		byte[] rawPublicKeyData = pubKeyInfo.getEncoded(); 
		
		//We need to close the PEM parser when finished
		keyReader.close();
		
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(rawPublicKeyData);
	    KeyFactory keyFact = KeyFactory.getInstance("RSA", "BC");
	    return keyFact.generatePublic(x509KeySpec);		
	}
	
	/**
	 * Generate a test Public Key
	 * @return a public key string for testing
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws IOException 
	 */
	public static String generateTestPublicKey() throws	NoSuchAlgorithmException, 
															NoSuchProviderException, 
															InvalidKeySpecException, 
															IOException
	{
		SecureRandom random = new SecureRandom();
		
		//Create the initial Key Pair
		KeyPairGenerator generator;
		
		generator = KeyPairGenerator.getInstance("RSA","BC");
		
		generator.initialize(1024, random);
		
		KeyPair pair = generator.generateKeyPair();
		PublicKey pubKey = pair.getPublic();
		PrivateKey	privKey = pair.getPrivate();
		
		StringWriter stringWriter=new StringWriter();
		PEMWriter pemFormatWriter=new PEMWriter(stringWriter);
		pemFormatWriter.writeObject(pubKey);
		pemFormatWriter.close();
		
		String cookedPubKey = stringWriter.toString();
		
	    return cookedPubKey;
	    		
	}
	
	/**
	 * Encode public key as String
	 * @param p
	 * @return
	 */
	private static String publicKeyToString(PublicKey p) {

	    byte[] publicKeyBytes = p.getEncoded();
	    BASE64Encoder encoder = new BASE64Encoder();
	    return encoder.encode(publicKeyBytes);

	}
	
	
	/**
	 * Iterate through public key cache until we find matching serial number
	 * @param serialNumber
	 * @return
	 */
	private Keyring getKeyRingFromSerialNo(String serialNumber)
	{
		for (Keyring keyRing : publicKeyCache)
			if (keyRing.getSerialnumber().equals(serialNumber))
				return keyRing;
		
		//If no match, return null
		//TODO possibly throw an exception around here?
		return null;
	}
	
	
	/**
	 * Convert vector of certificates into chain
	 * @return the chain as a normal array
	 */
	public Certificate[] toCertificateChain()
	{
		return certificateCache.toArray(new Certificate[0]);
	}
	
	/**
	 * Extract a given Public Key object from a Serial Number
	 * @param serialNumber
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public PublicKey extractPublicKeyFromSerialNumber(String serialNumber) throws NoSuchAlgorithmException, InvalidKeySpecException 
	{
		//Extract a public key object from ID	
		currentKeyRing = this.getKeyRingFromSerialNo(serialNumber);
				
		byte[] keybytes = currentKeyRing.getPublickey().getBytes();
		byte[] decode = Base64.decodeBase64(keybytes);
				
		KeyFactory fact = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(decode);
				
		PublicKey pubKey = fact.generatePublic(x509KeySpec);
		
		return pubKey;
	}
	
	/**
	 * Return a list of public keys for a given user (by email)
	 * @param username
	 * @return
	 */
	public ArrayList<Keyring> downloadPublicKeys(String username) 
	{
		Session session = hibernateSessionFactory.openSession();
		
		String downloadQuery = "from Keyring where email = :myEmail";
		Query query = session.createQuery(downloadQuery);
		query.setParameter("myEmail", username);
		
		//TODO this line requires testing...
		@SuppressWarnings("unchecked")
		ArrayList<Keyring>  pubKeys = (ArrayList<Keyring>) query.list();
		
		session.close();
		
		return pubKeys;
	}
	
	/**
	 * Return a single public key for given user & serial number
	 * @param username
	 * @param serialnumber
	 * @return
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	public String downloadPublicKey(String username, String serialnumber) throws NoSuchAlgorithmException, 
																				   NoSuchProviderException, 
																				   InvalidKeySpecException, 
																				   IOException
	{
		Session session = hibernateSessionFactory.openSession();
		
		String downloadQuery = "from Keyring where email = :myEmail and serialnumber = :mySerial";
		Query query = session.createQuery(downloadQuery);
		query.setParameter("myEmail", username);
		query.setParameter("mySerial", serialnumber);
		
		Keyring keyring = (Keyring) query.uniqueResult();
		
		session.close();
		
		//Now we need to extract keyring data to standardised Byte[]
		
		PublicKey pubKey = stringToPublicKey(keyring.getPublickey());
		
		StringWriter stringWriter=new StringWriter();
		PEMWriter pemFormatWriter=new PEMWriter(stringWriter);
		pemFormatWriter.writeObject(pubKey);
		pemFormatWriter.close();
		
		String cookedPubKey = stringWriter.toString();
	    
	    return cookedPubKey;
	}
	
	/**
	 * Return an array of public key serial numbers, by username
	 * @param username
	 * @return
	 */
	public String[] getPublicKeySerialNos(String username)
	{
		Session session = hibernateSessionFactory.openSession();
		
		String downloadQuery = "from Keyring where email = :myEmail";
		Query query = session.createQuery(downloadQuery);
		query.setParameter("myEmail", username);

		@SuppressWarnings("unchecked")
		ArrayList<Keyring>  keyrings = (ArrayList<Keyring>) query.list();
		
		//Here we extract a collection of serial identifier strings..
		ArrayList<String> serialNoStrings = new ArrayList<String>();
		for(Keyring k : keyrings)
		{
			serialNoStrings.add(k.getSerialnumber());
		}
		
		String[] serialNumbers = new String[serialNoStrings.size()];
		serialNumbers = serialNoStrings.toArray(serialNumbers);
		
		return serialNumbers;
	}
	
	/**
	 * Return a list of user names, from a given search string.
	 * @param searchText
	 * @return
	 */
	public String[] getUserNames(String searchText)
	{
		Session session = hibernateSessionFactory.openSession();

		String downloadQuery = "from User where email like :mySearch";
		Query query = session.createQuery(downloadQuery);
		query.setParameter("mySearch", searchText + "%");
		
		@SuppressWarnings("unchecked")
		ArrayList<User> users = (ArrayList<User>) query.list();
		
		//Here we extract the list of User names
		ArrayList<String> usernameStrings = new ArrayList<String>();
		for(User u: users)
		{
			usernameStrings.add(u.getEmail());
		}
		
		String[] userNames = new String[usernameStrings.size()];
		userNames = usernameStrings.toArray(userNames);
		
		return userNames;
	}
	
	
	/***
	 * Returns the key pair for the System account
	 * @return the system key pair
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	private KeyPair getSystemKeyPair(String password, String keyStore) throws KeyStoreException, 
																				UnrecoverableKeyException, 
																				NoSuchAlgorithmException, 
																				CertificateException, 
																				IOException
	{
		FileInputStream is = new FileInputStream(keyStore);
	    privateKeyStore.load(is, password.toCharArray());

	    String alias = INTERMEDIATE_ALIAS;

	    Key key = privateKeyStore.getKey(alias, password.toCharArray());
	    if (key instanceof PrivateKey) 
	    {
	    	// Get public key from stored certificate
	    	java.security.cert.Certificate cert = privateKeyStore.getCertificate(alias);
	    	PublicKey publicKey = cert.getPublicKey();

	    	// Construct and return a key-pair
	    	return new KeyPair(publicKey, (PrivateKey) key);
	    }
	    
	    return null;
	}
	
	/**
	 * Convert from an X509 Cert to PEM
	 * @param x509Cert
	 * @return
	 * @throws CertificateEncodingException
	 */
	private static String convertToPem(X509Certificate x509Cert) throws CertificateEncodingException 
	{
		 Base64 encoder = new Base64(64);
		 String cert_begin = "-----BEGIN CERTIFICATE-----\n";
		 String end_cert = "-----END CERTIFICATE-----";

		 byte[] derCert = x509Cert.getEncoded();
		 String pemCertPre = new String(encoder.encode(derCert));
		 String pemCert = cert_begin + pemCertPre + end_cert;
		 return pemCert;
	}
	
	/***
	 * Load a user object, by email
	 * @param userEmail
	 * @param currSession
	 * @return
	 */
	private User loadUser(String userEmail, Session currSession)
	{
		String downloadQuery = "from User where email = :myEmail";
		Query query = currSession.createQuery(downloadQuery);
		query.setParameter("myEmail", userEmail);
		
		User newUser = (User) query.uniqueResult();
		
		return newUser;
	}
	
	//-------------- Exportable functions ------------------ //
	
	/**
	 * Publish a given public key on our Web Service
	 * @param userEmail
	 * @param rawPubKeyText
	 * @throws Exception
	 */
	public void publishPublicKey(String userEmail, String pubKeyText) throws 	Exception
	{
		PublicKey pubKey = stringToPublicKey(pubKeyText);
		
		//First we need to generate a Serial Number    
		String serialNumber = CryptoUtil.generateSerialNumber(pubKeyText);
		
		//Generate X509 Certificate for this key
		//signed using the System key-pair.
		Session session = hibernateSessionFactory.openSession();
				
		//Load the system user
		//User systemUser = loadUser("flynn@encom.com", session);
		
		Keyring systemKeyRing = new Keyring();
		systemKeyRing.setSerialnumber("41be-b1ee8-7e26-27c5d");
		
		//Get the private key from file
		String keyStoreID = "private_" + systemKeyRing.getSerialnumber();
		
		KeyPair systemKeyPair = getSystemKeyPair("reindeer2048", keyStoreID);
		
		//Issue a root-level certificate for the current user's public key.
		X509Certificate rootCert = certificateManager.issueRootCert(pubKey, systemKeyPair.getPrivate());
		
		//Now we can save a new user to the database		
		User newUser = new User(userEmail, "17293", "GL45JY");
		
		//Initiate the transaction
		session.beginTransaction();
		
		currentUser = newUser;
		currentKeyRing.setUser(currentUser);
		currentKeyRing.setPublickey(pubKeyText);
		currentKeyRing.setSerialnumber(serialNumber);

		currentUser.getKeyrings().add(currentKeyRing);
		
		//Prepare the certification data..,
		byte[] data = CryptoUtil.convertToByteArray(rootCert);
		
		currentRootCert.setUser(currentUser);
		currentRootCert.setKeyring(currentKeyRing);
		currentRootCert.setData(data);

		currentKeyRing.getCertificates().add(currentRootCert);
		
		//Save all the User credentials
		session.save(currentUser);
	    session.save(currentKeyRing);
	    session.save(currentRootCert);
	    
	    //commit and close the Hibernate transaction	    
	    session.getTransaction().commit();
		session.close();
		
	}
	
	
	
	/**
	 * Generate and persist a Key Pair, Database and Keystore
	 * @throws Exception 
	 */
	
	public void generateKeyPair() throws 	Exception { 
	
		SecureRandom random = new SecureRandom();
		
		//Create the initial Key Pair
		KeyPairGenerator generator;
		
		generator = KeyPairGenerator.getInstance("RSA","BC");
		
		generator.initialize(1024, random);
		
		KeyPair pair = generator.generateKeyPair();
		PublicKey pubKey = pair.getPublic();
		PrivateKey	privKey = pair.getPrivate();
		
		//Convert public key to PEM format
		StringWriter stringWriter=new StringWriter();
		PEMWriter pemFormatWriter=new PEMWriter(stringWriter);
		pemFormatWriter.writeObject(pubKey);
		pemFormatWriter.close();
		
		String cookedPubKey = stringWriter.toString();
		
	    
		//Now add the public key string to Keyring	
	    currentKeyRing.setPublickey(cookedPubKey);
	    
	    
	    //Start Hibernate session
	    
	    Session session = hibernateSessionFactory.openSession();
	    
	    //Generate our Public Key Serial Number 
	    String serialNumber = CryptoUtil.generateSerialNumber(currentKeyRing.getPublickey());
	    
	    //Do the transaction
	    
	    session.beginTransaction();
	    
	    //Generate and save serial number for the key pair
	    
	    currentKeyRing.setUser(currentUser);
	    currentKeyRing.setSerialnumber(serialNumber);
	     
	    //Persist key ring to User's key bunch
	  
	    currentUser.getKeyrings().add(currentKeyRing);
	    
	    //Generate a certification request
	    
	    PKCS10CertificationRequest request = certificateManager.generateRequest(pair);
	   
	    //Process the request, generating a certificate and credentials
	   
	    X509Certificate interCertificate =  certificateManager.processRequest(request, pair);
	    X509Certificate rootCertificate = certificateManager.getRootCertificate();
	    
	    
	    X500PrivateCredential rootCredential = certificateManager.toX500PrivateCredential(privKey, rootCertificate, ROOT_ALIAS); 
	    X500PrivateCredential interCredential = certificateManager.toX500PrivateCredential(privKey, interCertificate, INTERMEDIATE_ALIAS);
	    
	    //Add certificates to internal cache

	    //First build certificate entries
	    //TODO add further certificates in the chain...
	    
	    byte[] data = CryptoUtil.convertToByteArray(interCertificate);
	    	    
	    currentRootCert.setData(data);
	    currentRootCert.setUser(currentUser);
	    currentRootCert.setKeyring(currentKeyRing);

	    currentKeyRing.getCertificates().add(currentRootCert);
	    
	    session.save(currentUser);
	    session.save(currentKeyRing);
	    session.save(currentRootCert);
	    
	    //commit and close the Hibernate transaction
	    
	    session.getTransaction().commit();
	    session.close();
	    
		//Save the private key in key store on disk
	    //TODO Refactor this by creating a certificate cache
	    
	    X509Certificate[] chain = new X509Certificate[2];
	    
	    chain[0] = rootCredential.getCertificate();
	    chain[1] = interCredential.getCertificate();
	    	    
	    privateKeyStore.setCertificateEntry(rootCredential.getAlias(),
	    									rootCredential.getCertificate());
	    
	    privateKeyStore.setKeyEntry(interCredential.getAlias(),
	    							interCredential.getPrivateKey(),
	    							currentUserPassword.toCharArray(),
	    							chain);
	    
	    FileOutputStream fos = new FileOutputStream("private_" + currentKeyRing.getSerialnumber());
	    
	    privateKeyStore.store(fos, currentUserPassword.toCharArray());
	    
	    fos.close();
	    
	    
	    
	}
	
	/**
	 * Encrypt a File, given a public key ID
	 * 
	 * @param filename
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws IOException 
	 */
	
	public void encrypt(String filename, String serialNumber) throws NoSuchAlgorithmException, 
																	 NoSuchProviderException, 
																	 NoSuchPaddingException, 
																	 InvalidKeySpecException, 
																	 InvalidKeyException, 
																	 IllegalBlockSizeException, 
																	 BadPaddingException, 			
																	 IOException 
	{
		
		//Extract a public key object from ID	
		PublicKey pubKey = extractPublicKeyFromSerialNumber(serialNumber);
		
		//Open the file into a byte array
		
		byte [] input = CryptoUtil.getTextFromFile(filename).getBytes();
		
		//Generate a random seed for the encryption
		
		SecureRandom seed = new SecureRandom();
		
		//Do the actual encryption
		
		Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey, seed);
				
		byte[] cipherText = cipher.doFinal(input);
		
		//Save the encrypted file
		
		CryptoUtil.saveToTextFile(filename, cipherText);
		
		
	}
	
	public void decrypt(String filename) throws	UnrecoverableKeyException, 
																	KeyStoreException, 
																	NoSuchAlgorithmException, 
																	IOException, 
																	NoSuchProviderException, 
																	NoSuchPaddingException, 
																	InvalidKeyException, 
																	IllegalBlockSizeException, 
																	BadPaddingException 
	{
		
		//Get the private key from key store, based on certificate		
		PrivateKey privKey = (PrivateKey) privateKeyStore.getKey(INTERMEDIATE_ALIAS, currentUserPassword.toCharArray());
				
		//Open the file into a byte array
				
		byte [] input = CryptoUtil.getTextFromFile(filename).getBytes();
						
		//Do the actual decryption
				
		Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
						
		byte[] cipherText = cipher.doFinal(input);
				
		//Save the decrypted file
				
		CryptoUtil.saveToTextFile(filename, cipherText);
	}
	
	/**
	 * Digitally sign a document with a private key
	 * @param filename
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 * @throws IOException 
	 * @throws CertificateException 
	 */
	public byte[] sign(String filename) throws 	NoSuchAlgorithmException, 
												NoSuchProviderException, 
												UnrecoverableKeyException, 
												KeyStoreException, 
												InvalidKeyException, 
												SignatureException, 
												CertificateException, 
												IOException { 
		
		PrivateKey privKey;
		
		//get the private key from key store, based on certificate		
		privKey = (PrivateKey) privateKeyStore.getKey(INTERMEDIATE_ALIAS, currentUserPassword.toCharArray());
		
		Signature signature = Signature.getInstance("SHA1withRSA", "BC");
		
		//generate a signature based on this private key
		signature.initSign(privKey);
		signature.update(filename.getBytes());
		
		return signature.sign();
		
	}
	
	/**
	 * Verify a signature on a signed document, by public key
	 * @param filename
	 * @param sigBytes
	 * @param serialNumber
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws InvalidKeySpecException
	 */
	public boolean verify(String filename, byte[] sigBytes, String serialNumber) throws	NoSuchAlgorithmException, 
																						NoSuchProviderException, 
																						InvalidKeyException, 
																						SignatureException, 
																						InvalidKeySpecException 
	{  
		//set up the Signature object
		Signature signature = Signature.getInstance("SHA1withRSA", "BC");
		
		//Extract a public key object from ID
		PublicKey pubKey = extractPublicKeyFromSerialNumber(serialNumber);
		
		//do the verification
		signature.initVerify(pubKey);
		signature.update(filename.getBytes());
		
		boolean decision = signature.verify(sigBytes) ? true : false;
		
		return decision;
	}
	
}
