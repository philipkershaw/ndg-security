
/*
 * TokenReader.java
 *
 * Created on 26 October 2003, 21:50
 */

package uk.ac.cclrc.authorisation.client;
//import uk.ac.cclrc.authorisation.Config;
//import java.io.IOException;
//import java.io.PrintStream;
//import org.globus.gsi.CertUtil;
//import org.globus.gsi.OpenSSLKey;
//import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
//import uk.ac.cclrc.authorisation.util.*;
//import org.globus.util.Base64;
//import org.apache.xml.security.c14n.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import uk.ac.cclrc.authorisation.*;
import org.apache.log4j.*;
import org.jdom.*;
import org.jdom.input.*;
import org.jdom.output.*;
import java.util.*;
import java.io.*;
import ac.dl.xml.*;
import org.apache.xml.security.utils.*;
import org.apache.xml.security.signature.*;
import org.apache.xpath.XPathAPI;
import org.apache.xml.security.samples.utils.resolver.OfflineResolver;
import org.apache.xml.security.keys.KeyInfo;


public class TokenReader {
    
    private X509Certificate acServerCertificate;
    private PublicKey acServerPublicKey;
    private String messageText, certFile, basePath;
    private Properties prop;
    
    //use for Java KeyStore
    static Logger log = Logger.getLogger(TokenReader.class);
    RSAPublicKey pubKey;
    
    public TokenReader() throws IOException, CertificateException, GeneralSecurityException
    {
        // certFile = System.getProperty("user.home")+File.separator+".globus"+File.separator+"portalcert.pem";
        
        //System.out.println("cert difle "+certFile );
        //certFile = "/home/asm67/project/authorisation/certificates/escvig3Cert.pem";
        // acServerCertificate = CertUtil.loadCertificate(certFile.trim());
        
        // acServerPublicKey = acServerCertificate.getPublicKey();
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        //Using SUN Java Key Store for now
        prop = new Properties();
        try{
            prop.load(new FileInputStream(Config.getContextPath()+"authorisation.prop"));
        }
        catch(IOException ioe){
            log.error("Unable to find config file: "+Config.getContextPath()+"authorisation.prop",ioe);
            throw ioe;
        }
        basePath = prop.getProperty( "base_path" );
        if( basePath == null )
        {
            throw new GeneralSecurityException( "The base path to the directory where signed tokens are stored " +
                "is not specified in the config file" );
        }                        
        
        String filename = prop.getProperty("certificate");
        if(filename == null) throw new FileNotFoundException("keystore certificate not specified in config file");
        File certFile = new File(filename);
        if(!certFile.exists()) throw new FileNotFoundException("Keystore certificate: " + certFile.getAbsolutePath()+" not found on the system");
        InputStream inStream = new FileInputStream(certFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert1 = (X509Certificate)cf.generateCertificate(inStream);
        inStream.close();
        pubKey = (RSAPublicKey)cert1.getPublicKey();
    }

    // NOT USED FOR XML SIGNATURE
    /** Method to verify Attribute Certificate
     ** @param String attributeCertificate
     *  @return boolean true/false
     **/
    public AttributeList getAttributes(org.w3c.dom.Element authorisationToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAuthorisationTokenException, Exception {
        try {
            DOMBuilder builder = new DOMBuilder();
            Element root = builder.build(authorisationToken);
            List topElements = root.getChildren();
            Element acInfo = (Element)topElements.get( 0 );
            Element signature = (Element)topElements.get( 1 );
            
            if (verifyauthorisationToken(acInfo,signature)) {
                
                AttributeList al = new AttributeList(acInfo);
                
                if (al.isValid()) // check if remaining time is still present in Token
                    return al;
                else throw new InvalidAuthorisationTokenException("Token timeout, request for new token");
            } else {
                throw new InvalidAuthorisationTokenException("Signature does not match");
            }
        } catch (Exception e) {
            //log.error("Unexcepted error with getAttributes",e);
            throw e;
        }
    }
    
    // NOT USED FOR XML SIGNATURE    
    /** Method to verify Attribute Certificate
     * @param String messageText
     * @param String signatureText
     *  @return boolean true/false
     **/
    /*
    public boolean verifyauthorisationToken(String messageText, String signatureText)
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sigVerifier = Signature.getInstance("SHA1withRSA");
        sigVerifier.initVerify(acServerPublicKey);
        sigVerifier.update(messageText.getBytes());
        return sigVerifier.verify(signatureText.getBytes());
    }
     */

    // NOT USED FOR XML SIGNATURE    
    /** Method to verify Attribute Certificate
     * @param Element acInfo
     * @param Element signature
     *  @return boolean true/false
     **/
    private boolean verifyauthorisationToken(Element acInfo, Element signature)   throws NoSuchAlgorithmException, InvalidKeyException, SignatureException   {
        
        XMLOutputter outputter = new XMLOutputter();
        String messageText = outputter.outputString(acInfo);
        Namespace sigNS = signature.getNamespace();
        String signatureText = signature.getChild("SignatureValue",sigNS).getText();
        String sigMethodText = signature.getChild("SignedInfo",sigNS).getChild("SignatureMethod",sigNS).getText();
        String digestMethodText = signature.getChild("SignedInfo",sigNS).getChild("Reference",sigNS).getChild("DigestMethod",sigNS).getText();
        //decode the signiture text
        byte[] decode = org.globus.util.Base64.decode(signatureText.getBytes());
        
        Signature sigVerifier = Signature.getInstance( digestMethodText + "with" + sigMethodText );
        sigVerifier.initVerify(pubKey);
        sigVerifier.update(messageText.getBytes());
        
        
        if(!sigVerifier.verify(decode)){
            
            
            return false;
        }
        else return true;
        
    }
    
    // INCLUDED FOR XML SIGNATURE    
    /** This method takes a digitally signed authorisation token and extracts the attribute list,
     * i.e. the user's personal attributes
     *@param org.w3c.dom.Element authorisationToken The signed authorisation token
     *@exception java.lang.Exception
     *@exception uk.ac.cclrc.authorisation.client.InvalidAuthorisationTokenException
     *@return uk.ac.cclrc.authorisation.AttributeList the user's personal attributes
     */        
    public AttributeList getACInfo(org.w3c.dom.Element authorisationToken) throws InvalidAuthorisationTokenException, Exception {
       
        Document jdomAttList = Converter.DOMtoJDOM( authorisationToken.getOwnerDocument() );
        AttributeList tempAttList = new AttributeList( jdomAttList.getRootElement().getChild("acInfo") );
        String issuerName = tempAttList.getIssuerName();
        String holder = tempAttList.getHolder();
        byte[] holderBytes = holder.getBytes();
        
        byte[] encodedHolderBytes = org.globus.util.Base64.encode( holderBytes );
        String encodedHolderString = new String( encodedHolderBytes );
        
        String signatureFileName = basePath + issuerName + "_" + encodedHolderString + ".xml";

        boolean schemaValidate = false;
       
        Element acInfo = null;
        DOMBuilder builder = new DOMBuilder();
        Element root = builder.build(authorisationToken);
        List topElements = root.getChildren();
        acInfo = (Element)topElements.get( 0 );
 
/*
        Element signatureElement = null; 
        signatureElement = (Element)topElements.get( 1 );
 */

  //      final String signatureSchemaFile = "data/xmldsig-core-schema.xsd";
        
        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
/*
        if( schemaValidate )
        {
            dbf.setAttribute("http://apache.org/xml/features/validation/schema", Boolean.TRUE);
            dbf.setAttribute( "http://apache.org/xml/features/dom/defer-node-expansion", Boolean.TRUE);
            dbf.setValidating(true);
            dbf.setAttribute("http://xml.org/sax/features/validation", Boolean.TRUE);
        }
*/
        dbf.setNamespaceAware(true);
        dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);

        /*
        if( schemaValidate )
        {
            dbf.setAttribute( "http://apache.org/xml/properties/schema/external-schemaLocation",
                Constants.SignatureSpecNS + " " + signatureSchemaFile);
        }
         */
        File f = new File(signatureFileName);

        System.out.println("**********************************************");
        //System.out.println("Try to verify signature file associated with the authorisation token whose data is to be extracted");
        System.out.println("Try to verify signed authorisation token file whose data is to be extracted");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");

        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        db.setErrorHandler(new org.apache.xml.security.utils.IgnoreAllErrorHandler());

        /*
        if( schemaValidate )
        {
            db.setEntityResolver(new org.xml.sax.EntityResolver()
            {
                public org.xml.sax.InputSource resolveEntity( String publicId, String systemId)
                  throws org.xml.sax.SAXException
                {
                    if (systemId.endsWith("xmldsig-core-schema.xsd"))
                    {
                        try
                        {
                            return new org.xml.sax.InputSource(
                                new FileInputStream(signatureSchemaFile));
                        }
                        catch (FileNotFoundException ex)
                        {
                            throw new org.xml.sax.SAXException(ex);
                        }
                    }
                    else
                    {
                        return null;
                    }
                }
            } );
        }
*/
        org.w3c.dom.Document doc = db.parse(new java.io.FileInputStream(f));

        //org.w3c.dom.Document doc = authorisationToken.getOwnerDocument();
        
        org.w3c.dom.Element nscontext = XMLUtils.createDSctx(doc, "ds", Constants.SignatureSpecNS);
        org.w3c.dom.Element sigElement = (org.w3c.dom.Element) XPathAPI.selectSingleNode( doc,
            "//ds:Signature[1]", nscontext);
        XMLSignature signature = new XMLSignature(sigElement, f.toURL().toString());

        signature.addResourceResolver(new OfflineResolver());

        KeyInfo ki = signature.getKeyInfo();

        if (ki != null)
        {
            X509Certificate cert = ki.getX509Certificate();
            if (cert != null)
            {
                boolean validSignature = signature.checkSignatureValue(cert);
                if( !validSignature )
                {
                    log.error( "The XML signature in the authorisation token is invalid" );
                    throw new InvalidAuthorisationTokenException( "The XML signature in the authorisation token is invalid" );
                }
                else
                {
                    System.out.println("Signature is valid");
                }
            }
            else
            {
                PublicKey pk = signature.getKeyInfo().getPublicKey();

                if (pk != null)
                {
                    System.out.println("**********************************************");
                    System.out.println("Try to verify the signature using the public key");
                    System.out.println("//////////////////////////////////////////////");
                    System.out.println("");
                    System.out.println("");

                    boolean validSignature = signature.checkSignatureValue( pk );
                    if( !validSignature )
                    {
                        log.error( "The XML signature in the authorisation token is invalid" );
                        throw new InvalidAuthorisationTokenException( "The XML signature in the authorisation token is invalid" );
                    }

                }
                else
                {
                    throw new GeneralSecurityException( "Did not find a public key or certificate, so can't check the signature" );
                }
            }
        }
        else
        {
            throw new GeneralSecurityException( "Did not find KeyInfo, so can't check the signature" );
        }

        AttributeList al = new AttributeList(acInfo);
                
        if (al.isValid()) // check if remaining time is still present in Token
            return al;
        else
            throw new InvalidAuthorisationTokenException("Token timeout, request for new token");
    }
    
    // INCLUDED FOR XML SIGNATURE    
    static
    {
      org.apache.xml.security.Init.init();
    }

}
