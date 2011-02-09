package uk.ac.cclrc.authorisation;

//import java.io.*;
//import org.apache.xml.security.*;
//import uk.ac.cclrc.authorisation.util.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.io.*;
import org.jdom.*;
import org.jdom.output.*;
import org.apache.log4j.*;
import java.util.*;
import org.apache.xml.security.utils.*;
import org.apache.xml.security.signature.*;
import org.apache.xml.security.transforms.*;
import ac.dl.xml.*;


public class ACGen {
    
    private X509Certificate hostCertificate;
    private PrivateKey hostPrivateKey;
    private PublicKey hostPublicKey;
    private String messageText, certFile, keyFile, basePath;
    private java.security.cert.X509Certificate x509Cert;

    //use for Java KeyStore
    private RSAPublicKey pubKey;
    private String signatureAlgorithm, digestAlgorithm;
    private PrivateKey newPrvKey;
    
    static Logger log = Logger.getLogger(ACGen.class);
    
    
    public ACGen() throws IOException, GeneralSecurityException {
        // certFile = System.getProperty("user.home")+File.separator+".globus"+File.separator+"portalcert.pem";
        //keyFile = System.getProperty("user.home")+File.separator+".globus"+File.separator+"portalkey.pem";
        //openHostKey(certFile, keyFile);
        
        //Using SUN Java Key Store for now
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        loadKeyStore();
        
    }
    //not needed
    /*
    public String getACInString(String attributeString)
    throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        messageText = attributeString;
        Signature signer = Signature.getInstance(digestAlgorithm + "with" + signatureAlgorithm);
        signer.initSign(prvKey);
        signer.update(messageText.getBytes());
        byte signatureBytes[] = signer.sign();
        
        //return Base64 encoding of the signature
        byte[] encode = org.globus.util.Base64.encode(signatureBytes);
        BufferedReader reader= new BufferedReader(new InputStreamReader(new ByteArrayInputStream(encode)));
        String stringEncoding = "";
        try{
            stringEncoding = reader.readLine();
            reader.close();
        }
        catch(Exception e){
            try{
                reader.close();
            }
            catch(Exception ignore){}
        }
        return stringEncoding;
    }
    */
    
    // NOT USED FOR XML SIGNATURE        
    /** Method generates signature of the message using the pvt key of server */
    /*
    public String getSignatureString(String attributeString) throws Exception{
        messageText = attributeString;
        Signature signer = Signature.getInstance(digestAlgorithm + "with" + signatureAlgorithm);
        signer.initSign(prvKey);
        signer.update(messageText.getBytes());
        byte signatureBytes[] = signer.sign();
        
        //return Base64 encoding of the signature
        byte[] encode = org.globus.util.Base64.encode(signatureBytes);
        BufferedReader reader= new BufferedReader(new InputStreamReader(new ByteArrayInputStream(encode)));
        String stringEncoding = "";
        try{
            stringEncoding = reader.readLine();
            reader.close();
        }
        catch(Exception e){
            try{
                
                reader.close();
            }
            catch(Exception ignore){}
        }
        return stringEncoding;
    }
    */
   
    // INCLUDED FOR XML SIGNATURE    
    /** Signs an unsigned user attribute list and returns the resulting authorisation token as a JDOM document
     *@param AttributeList attList The user's personal attribute details
     *@exception Exception
     *@return org.jdom.Document The signed authorisation token
     */            
    public Document sign( AttributeList attList ) throws Exception
    {
        // get User Access privileges from Database
        org.w3c.dom.Document doc = attList.getDOMDocument();
        Constants.setSignatureSpecNSprefix("");
        
        String issuerName = attList.getIssuerName();
        String holder = attList.getHolder();
        byte[] holderBytes = holder.getBytes();
        byte[] encodedHolderBytes = org.globus.util.Base64.encode( holderBytes );
        String encodedHolderString = new String( encodedHolderBytes );
        File signatureFile = new File( basePath + issuerName + "_" + encodedHolderString + ".xml");
       
        XMLSignature sig = null;

        String baseURI = signatureFile.toURL().toString();

        System.out.println("**********************************************");
        System.out.println("Get signature algorithm type from properties file");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( signatureAlgorithm );
        System.out.println("");         

        //Create an XML Signature object from the document, BaseURI and signature algorithm
        if( signatureAlgorithm.equals( "RSA" ) )
        {
            sig = new XMLSignature(doc, baseURI, XMLSignature.ALGO_ID_SIGNATURE_RSA);
        }
        else if( signatureAlgorithm.equals( "DSA" ) )
        {
            sig = new XMLSignature(doc, baseURI, XMLSignature.ALGO_ID_SIGNATURE_DSA);
        }
        else
        {
            throw new GeneralSecurityException( "signature algorithm specified in config file not valid" );
        }

        org.w3c.dom.Element root = doc.getDocumentElement();


        //Append the signature element to the root element before signing because
        //this is going to be an enveloped signature (i.e. enveloped by the document).
        //Two other possible forms are enveloping where the document is inside the
        //signature and detached where they are separate.
        root.appendChild(sig.getElement());

        sig.getSignedInfo()
         .addResourceResolver(new org.apache.xml.security.samples.utils.resolver
            .OfflineResolver());

        System.out.println("**********************************************");
        System.out.println("Append signature element to token before signing" +
            "because this will be an enveloped signature");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");         

        //create the transforms object for the Document/Reference
        Transforms transforms = new Transforms(doc);

        //First we have to strip away the signature element (it's not part of the
        //signature calculations). The enveloped transform can be used for this.
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);

        System.out.println("**********************************************");
        System.out.println("Specify that transform must be used which strips away signature element before signing");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");         

        //Part of the signature element needs to be canonicalized. It is a kind
        //of normalizing algorithm for XML.
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);

        System.out.println("**********************************************");
        System.out.println("Specify canonicalisation transform to be used.");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");         

        //Add the above Document
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        System.out.println("**********************************************");
        System.out.println("Specify digest algorithm to be used.");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");         

        sig.addKeyInfo(x509Cert);
        sig.addKeyInfo(x509Cert.getPublicKey());

        System.out.println("**********************************************");
        System.out.println("Add key information to the signature");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");         

        sig.sign( newPrvKey );

        System.out.println("**********************************************");
        System.out.println("Perform actual signing");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");         

        FileOutputStream f = new FileOutputStream(signatureFile);
        //XMLUtils.outputDOMc14nWithComments(doc, f);
	XMLOutputter outputter = new XMLOutputter();
        
        System.out.println("");                        
        System.out.println("");                
        
        Document jdomDoc = Converter.DOMtoJDOM( doc );
        outputter.output( jdomDoc, f );
        f.close();        

        return jdomDoc;
    }
    
    // NOT USED FOR XML SIGNATURE    
    /*
    public String getDigestString(String attributeString) throws Exception{
        messageText = attributeString;
        MessageDigest digester = MessageDigest.getInstance(digestAlgorithm);
        digester.update(messageText.getBytes());
        byte digestBytes[] = digester.digest();
        
        //return Base64 encoding of the signature
        byte[] encode = org.globus.util.Base64.encode(digestBytes);
        BufferedReader reader= new BufferedReader(new InputStreamReader(new ByteArrayInputStream(encode)));
        String stringEncoding = "";
        try{
            stringEncoding = reader.readLine();
            reader.close();
        }
        catch(Exception e){
            try{
                
                reader.close();
            }
            catch(Exception ignore){}
        }
        return stringEncoding;
    }
    */
    
    /*
    //use when this works
    private void openHostKey(String certFile, String keyFile)
    throws IOException, GeneralSecurityException, InvalidKeyException {
        //OpenSSLKey key = new BouncyCastleOpenSSLKey(keyFile.trim());
        
        //hostPrivateKey = key.getPrivateKey();
        //hostCertificate = CertUtil.loadCertificate(certFile.trim());
        // hostPublicKey = hostCertificate.getPublicKey();
    }
     */
    
    // NOT USED FOR XML SIGNATURE    
    /*
    public boolean verifyAttributeCertificate(String messageText, String signatureText)
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        
        byte[] decode = org.globus.util.Base64.decode(signatureText.getBytes());
        Signature sigVerifier = Signature.getInstance(digestAlgorithm + "with" + signatureAlgorithm);
        sigVerifier.initVerify(pubKey);
        sigVerifier.update(messageText.getBytes());
        return sigVerifier.verify(decode);
    }
     */
    
    // AMENDED FOR XML SIGNATURE
    /** Extracts the value of the specified element within the DN
     *@exception java.io.IOException
     *@exception java.security.GeneralSecurityException
     */            
    private void loadKeyStore() throws IOException, GeneralSecurityException{
        
        Properties prop = new Properties();
        try{
            prop.load(new FileInputStream(Config.getContextPath()+"authorisation.prop"));
        }
        catch(IOException ioe){
            log.error("Unable to find config file: "+Config.getContextPath()+"authorisation.prop",ioe);
            throw ioe;
        }
        
        
        //String keyStoreFileName = System.getProperty("user.home")+File.separator+".keystore";
        String keyStoreType = prop.getProperty("keystore_type");
        if( keyStoreType == null )
        {
            throw new GeneralSecurityException( "The type of keystore is not specified in the config file" );
        }                
        
        String keyStoreFileName = prop.getProperty("keystore");
        String keyStorePasswd = prop.getProperty("keystore_passwd");
        String keyStoreAlias = prop.getProperty("keystore_alias");
        if( keyStoreAlias == null )
        {
            throw new GeneralSecurityException( "The keystore alias is not specified in the config file" );
        }                
        
        signatureAlgorithm = prop.getProperty("signature_algorithm");
        if( signatureAlgorithm == null )
        {
            throw new GeneralSecurityException( "The signature algorithm to be applied to the attribute certificate " +
                "is not specified in the config file" );
        }                
        /*
        digestAlgorithm = prop.getProperty("digest_algorithm");
        if( digestAlgorithm == null )
        {
            throw new GeneralSecurityException( "The digest algorithm to be applied to the attribute certificate " +
                "is not specified in the config file" );
        }                
        */
        basePath = prop.getProperty("base_path");
        if( basePath == null )
        {
            throw new GeneralSecurityException( "The base path to the directory where signed tokens are stored " +
                "is not specified in the config file" );
        }                        
        // System.out.println(keyStoreFileName);
        if(keyStoreFileName == null || keyStoreFileName.equals("")) keyStoreFileName = System.getProperty("user.home")+File.separator+".keystore";
        if(keyStorePasswd == null || keyStorePasswd.equals("")) keyStorePasswd = "changeit";
        
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        keystore.load(new FileInputStream(keyStoreFileName), keyStorePasswd.toCharArray());
        Key key = keystore.getKey(keyStoreAlias, keyStorePasswd.toCharArray());
        if(key == null)throw new GeneralSecurityException("No private key loaded");
        newPrvKey = (PrivateKey)key;
        //prvKey = (RSAPrivateKey)key;
        java.security.cert.Certificate cert = keystore.getCertificate(keyStoreAlias);
        
        x509Cert = (java.security.cert.X509Certificate)cert;
        
        if(x509Cert == null)throw new GeneralSecurityException("No certificate loaded");
        pubKey = (RSAPublicKey)cert.getPublicKey();
        
        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get authorisation server's private and public keys from its keystore to allow creation of digital signature");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");         
    }
    /*
    public static void main(String args[]) {
        try {
            ACGen acGen = new ACGen();
            
            String messageString = "This is the string to be tested...";
            String signature = acGen.getSignatureString(messageString);
            
            System.out.println(signature);
            
            System.out.println(acGen.verifyAttributeCertificate(messageString, signature));
        }
        catch(Exception e) {
            log.warn(e);
        }
    }
     */
    
    // INCLUDED FOR XML SIGNATURE
    static {
        org.apache.xml.security.Init.init();
    }

}
