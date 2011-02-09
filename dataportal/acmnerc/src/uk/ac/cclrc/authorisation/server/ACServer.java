package uk.ac.cclrc.authorisation.server;
/* This class generates the authorisation Token for the user interacts with Database to
 * retrieve user Privileges, uses ACGen to sign Token and uses AttributeList to generate XML of attributes.
 * ACServer.java
 *
 * Created on July 17, 2003, 1:09 PM
 */

import uk.ac.cclrc.authorisation.*;
import uk.ac.cclrc.authorisation.client.*;
import uk.ac.cclrc.authorisation.util.*;
import org.globus.gsi.GlobusCredential;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import org.ietf.jgss.GSSCredential;
import java.security.*;
import java.security.interfaces.*;
import java.security.cert.*;
import java.io.*;
import ac.dl.xml.*;
import org.jdom.*;
import org.jdom.input.*;
import org.jdom.output.*;
import java.sql.*;
import org.apache.log4j.*;
import java.util.*;
//import org.ietf.jgss.GSSName;
//import org.gridforum.jgss.ExtendedGSSManager;
//import org.globus.gsi.CertUtil;
//import org.globus.gsi.OpenSSLKey;
//import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
//import java.security.cert.X509Certificate;
//import java.security.InvalidKeyException;
//import java.sql.SQLException;
//import java.lang.ClassNotFoundException;
//import java.net.*;
//import org.globus.util.Base64;
//import org.apache.xml.security.utils.*;

/**
 * @author  asm67
 *Read userCertificate, hostCertificate
 *Generate XML Attribute list
 *Sign
 *Create XML Attribute Certificate
 *Serialize AC to XML string or W3C dom object
 */
public class ACServer {
    
    private Properties prop;
    private StringFormatter sf;    
    private String version="1.0";
    private String issuerSerialNumber = "1"; // serial counter not yet implemented    
    private String certFile, facility, signatureAlgorithm, server, port, dbName, userName, tokenLifetime, userDn;
    private String canonicalization, digestAlgorithm, canonURL, signatureURL, sigMethodURL, referenceURL, digestURL;
    private String password, dbDriverString, dbDriverClass, stdRolesQuery, demoRolesQuery;
    private String userQuery, mappedRolesQuery1, mappedRolesQuery2;    
    private String dbDNstartValue, dbDNequalityString, dbDNdelimString;
    private String extdbDNstartValue, extdbDNequalityString, extdbDNdelimString;
    private String affilOrgsQuery, affilOrgsQuery2, mapFilePath, mappingPreference, pubKeyQuery;
    
    static Logger log = Logger.getLogger(ACServer.class);
    private Connection conn;
    private Statement stat;
    private uk.ac.cclrc.authorisation.AttributeList list;
    
    /** Creates a new instance of ACServer */
    public ACServer() throws IOException,GeneralSecurityException,Exception{
        
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try{
            //set config properties here
            prop = new Properties();
            prop.load(new FileInputStream(Config.getContextPath()+"authorisation.prop"));
        }
        catch(IOException e){
            log.fatal("Config File Not Found: " +Config.getContextPath()+"authorisation.prop", e);
            throw e;
        }
        
        certFile = prop.getProperty("certificate");
        if( certFile == null )
        {
            throw new GeneralSecurityException( "The path to the certificate (associated with the private key " +
                "used to sign the attribute certificate) is not specified in the config file" );
        }

        facility = prop.getProperty("facility");
        if( facility == null )
        {
            throw new GeneralSecurityException( "The facility hosting this authorisation server is not specified " +
                "in the config file" );
        }
                
        server = prop.getProperty("server");
        if( server == null )
        {
            throw new GeneralSecurityException( "The name/URL of the database server containing the user/role data " +
                "is not specified in the config file" );
        }
        
        port = prop.getProperty("port");
        if( port == null )
        {
            throw new GeneralSecurityException( "The port for queries to the database server containing user/role data " +
                "is not specified in the config file" );
        }
        
        dbName = prop.getProperty("db_name");
        if( dbName == null )
        {
            throw new GeneralSecurityException( "The name of the database containing the user/role data " +
                "is not specified in the config file" );
        }
        
        userName = prop.getProperty("username");
        /*
        if( userName == null )
        {
            throw new GeneralSecurityException( "The user-name for queries to the database server containing user/role data" +
                "is not specified in the config file" );
        }
         */
        
        password = prop.getProperty("passwd");
        /*
        if( password == null )
        {
            throw new GeneralSecurityException( "The password for queries to the database server containing user/role data" +
                "is not specified in the config file" );
        }
         */
        
        signatureAlgorithm = prop.getProperty("signature_algorithm");
        if( signatureAlgorithm == null )
        {
            throw new GeneralSecurityException( "The signature algorithm to be used for digitally signing attribute certificates " +
                "is not specified in the config file" );
        }
        
        dbDriverString = prop.getProperty("db_driver_string");
        if( dbDriverString == null )
        {
            throw new GeneralSecurityException( "The database driver string used to get a connection to the user/role database " +
                "is not specified in the config file" );
        }        
        
        dbDriverClass = prop.getProperty("db_driver_class");
        if( dbDriverClass == null )
        {
            throw new GeneralSecurityException( "The jdbc database driver class used to get a connection to the user/role database " +
                "is not specified in the config file" );
        }                
        
        mappingPreference = prop.getProperty("mapping_preference");
        if( mappingPreference == null )
        {
            throw new GeneralSecurityException( "The preference for either a mapping file or a mapping database table " +
                "is not specified in the config file" );
        }        
        
        mapFilePath = prop.getProperty("map_file_location");
        if( !mappingPreference.equalsIgnoreCase( "database" ) && mapFilePath == null )
        {
            throw new GeneralSecurityException( "A mapping file will be used for role mappings yet the path of this file " +
                "is not specified in the config file" );
        }
        
        tokenLifetime = prop.getProperty("token_lifetime");
        if( tokenLifetime == null )
        {
            throw new GeneralSecurityException( "The standard lifetime for attribute certificates is not specified in the config file" );
        }            

        String quotedStdRolesQuery = prop.getProperty("std_roles_query");
        if( quotedStdRolesQuery == null )
        {
            throw new GeneralSecurityException( "The standard roles query is not specified in the config file" );
        }                
        sf = new StringFormatter( quotedStdRolesQuery );
        stdRolesQuery = sf.removeQuotes();
/*
        String quotedDemoRolesQuery = prop.getProperty("demo_roles_query");
        sf.setNewString( quotedDemoRolesQuery );
        demoRolesQuery = sf.removeQuotes();
*/
        String quotedAffilOrgsQuery = prop.getProperty("affil_orgs_query");
        if( quotedAffilOrgsQuery == null )
        {
            throw new GeneralSecurityException( "The affiliated organisations query is not completely specified in the config file" );
        }                
        sf.setNewString( quotedAffilOrgsQuery );
        affilOrgsQuery = sf.removeQuotes();

        String quotedAffilOrgsQuery2 = prop.getProperty("affil_orgs_query2");
        if( quotedAffilOrgsQuery2 == null )
        {
            throw new GeneralSecurityException( "The affiliated organisations query is not completely specified in the config file" );
        }                        
        sf.setNewString( quotedAffilOrgsQuery2 );
        affilOrgsQuery2 = sf.removeQuotes();

        dbDNstartValue = prop.getProperty("db_DN_start_value");
        if( dbDNstartValue == null )
        {
            throw new GeneralSecurityException( "The first field of distinguished names is not specified in the config file" );
        }
        if( !( dbDNstartValue.equalsIgnoreCase( "CN" ) || dbDNstartValue.equalsIgnoreCase( "C" ) ) )
        {
            throw new GeneralSecurityException( "The first field of distinguished names specified in the config file must be C or CN" );
        }

        String quotedDBDNequalityString = prop.getProperty("db_DN_equality_string");
        if( quotedDBDNequalityString == null )
        {
            throw new GeneralSecurityException( "The distinguished names equality string is not specified in the config file" );
        }        
        sf.setNewString( quotedDBDNequalityString );
        dbDNequalityString = sf.removeQuotes();            

        String quotedDBDNdelimString = prop.getProperty("db_DN_delim_string");            
        if( quotedDBDNdelimString == null )
        {
            throw new GeneralSecurityException( "The distinguished names delimiter string is not specified in the config file" );
        }                
        sf.setNewString( quotedDBDNdelimString );
        dbDNdelimString = sf.removeQuotes();     

        String quotedUserQuery = prop.getProperty("user_query");
        if( quotedUserQuery == null )
        {
            throw new GeneralSecurityException( "The user query is not specified in the config file" );
        }
        sf.setNewString( quotedUserQuery );
        userQuery = sf.removeQuotes();

        String quotedMappedRolesQuery1 = "";
        String quotedMappedRolesQuery2 = "";
        
        if( mappingPreference.equalsIgnoreCase( "database" ) )
        {
            quotedMappedRolesQuery1 = prop.getProperty("mapped_roles_query_pt1");
            if( quotedMappedRolesQuery1 == null )
            {
                throw new GeneralSecurityException( "The mapped roles query is not completely specified in the config file" );
            }
            sf.setNewString( quotedMappedRolesQuery1 );
            mappedRolesQuery1 = sf.removeQuotes();

            quotedMappedRolesQuery2 = prop.getProperty("mapped_roles_query_pt2");
            if( quotedMappedRolesQuery2 == null )
            {
                throw new GeneralSecurityException( "The mapped roles query is not completely specified in the config file" );
            }
            sf.setNewString( quotedMappedRolesQuery2 );
            mappedRolesQuery2 = sf.removeQuotes();            
        }

        String quotedPubKeyQuery = prop.getProperty("pub_key_query");
        sf.setNewString( quotedPubKeyQuery );
        pubKeyQuery = sf.removeQuotes();                        

        // not needed in XML signature
        /*
        canonicalization = prop.getProperty("canon_algorithm");
        digestAlgorithm = prop.getProperty("digest_algorithm");
        canonURL = prop.getProperty("canonicalization_URL");
        signatureURL = prop.getProperty("signature_URL");
        sigMethodURL = prop.getProperty("sigMethod_URL");
        referenceURL = prop.getProperty("reference_URL");
        digestURL = prop.getProperty("digest_URL");
         */
    }
    
    // NOT CURRENTLY USED
    /** This method is used to get authoriglobusCredentialsation Token describing the parameters of the user in XML string
     *@param String proxyCertificateInString proxyCertificate of the user in String
     *@exception java.lang.Exception
     *@return String XML string representation of the Authorizatino token for the user
     */
    public String getAuthorisationTokenInXML(String proxyCertString) throws Exception{
        
        Document doc = createAuthorisationToken(proxyCertString);
        Element el = doc.getRootElement();
        // Convert to XML String and Return
        XMLOutputter outputter = new XMLOutputter();
        
        outputter.setEncoding("");
        return outputter.outputString(el);
        
    }
    
    /** This method is used to get an Authorisation Token describing the user attributes as a w3c DOM object.
     * It is called when the user does not have a relevant token to pass to the data centre.
     *@param String proxyCertString proxy certificate of the user as a String
     *@exception java.lang.Exception
     *@return org.w3c.dom.Element the signed authorisation token expressed as a DOM Element
     */    
    public org.w3c.dom.Element getAuthorisationTokenInDOM(String proxyCertString ) throws Exception
    {
        org.w3c.dom.Element domAuthToken = getAuthorisationTokenInDOM( proxyCertString, null );
        return domAuthToken;
    }
    
    /** This method is used to get an Authorisation Token describing the user attributes as a w3c DOM object.
     * It is called directly when the user has a relevant token to pass in and indirectly when they don't
     * with extAuthToken set to null.
     *@param String proxyCertString proxy certificate of the user as a String
     *@param org.w3c.dom.Element extAuthToken user's authorisation token
     *@exception java.lang.Exception
     *@return org.w3c.dom.Element the signed authorisation token expressed as a DOM Element
     */
    public org.w3c.dom.Element getAuthorisationTokenInDOM(String proxyCertString, org.w3c.dom.Element extAuthToken) throws Exception{
        
        boolean userFound = searchDBForUser( proxyCertString );
        Document doc = null;
        
        if( userFound )
        {
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("User found in local database so original authorisation token will be generated");
            System.out.println("//////////////////////////////////////////////");
            System.out.println("");
            System.out.println("");

            doc = createAuthorisationToken(proxyCertString);
        }
        else
        {
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("User NOT found in local database.  Will now see if a mapped authorisation token is available / can be generated");
            System.out.println("//////////////////////////////////////////////");
            System.out.println("");
            System.out.println("");


            TokenReader reader = new TokenReader();

            if( extAuthToken != null )
            {
                list =  reader.getACInfo( extAuthToken );
                String authTokenProvenance = list.getProvenance();
                String issuerName = list.getIssuerName();

                System.out.println("**********************************************");
                System.out.println("Check provenance of current token");
                System.out.println("//////////////////////////////////////////////");
                System.out.println( authTokenProvenance );
                System.out.println("");

                if( authTokenProvenance.equals("mapped") )
                {
                    /*
                    if( issuerName.equalsIgnoreCase( facility ) )
                    {
                        System.out.println("**********************************************");
                        System.out.println("The user is passing in a mapped token that was issued by this data centre." );
                        System.out.println("An updated token will now be generated");
                        System.out.println("//////////////////////////////////////////////");
                        System.out.println("");
                        System.out.println("");
                        
                        //return extAuthToken;
                        doc = createMappedAuthorisationToken( proxyCertString, extAuthToken );
                    }
                    else
                    {
                     */
                        throw new InvalidAuthorisationTokenException( "Mapped Authorisation Tokens can not be used to generate further Authorisation Tokens - only Original Authorisation Tokens for affiliated institutions can be." );
                    //}
                }
                else
                {
                    doc = createMappedAuthorisationToken( proxyCertString, extAuthToken );
                }
            }
            else
            {
                throw new GeneralSecurityException( "To generate a mapped token, an original Authorisation Token from an affiliated institution must be passed in.  " +
                "To generate an original token, the user must be listed in the data centre's database" );
            }
        }
        if( doc != null )
        {
            org.w3c.dom.Document w3cDoc = Converter.JDOMtoDOM(doc);
            org.w3c.dom.Element el = w3cDoc.getDocumentElement();
            return el;
        }
        else
        {
            return null;
        }
    }

    
    // NOT CURRENTLY USED
    private PublicKey getPublicKey( String extOrg ) throws Exception
    {
        RSAPublicKey pubKey = null;
        
        if( mappingPreference.equals( "file" ) )
        {
            SAXBuilder saxb = new SAXBuilder();
            org.jdom.Document mapFileDoc = saxb.build( mapFilePath );
            Element root = mapFileDoc.getRootElement();
            List trustedElements = root.getChildren("trusted");
            Element trustedElement = null;
            String extPKPath = null;
            for( int i = 0; i < trustedElements.size(); i++ )
            {
                trustedElement = (Element)trustedElements.get( i );
                String trustedAttValue = trustedElement.getAttributeValue("name");
                if( trustedAttValue.equals( extOrg ) )
                {
                    extPKPath = trustedElement.getChildText( "ServerCertFile" );
                    break;
                }
            }
            
            File keyFile = new File( extPKPath );
            if( !keyFile.exists() )
            {
                throw new FileNotFoundException( "Key file: " + keyFile.getAbsolutePath()+" not found on the system" );            
            }
            InputStream inStream = new FileInputStream( keyFile );
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert1 = (X509Certificate)cf.generateCertificate(inStream);
            inStream.close();
            pubKey = (RSAPublicKey)cert1.getPublicKey();
            
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Extracted path of " + extOrg + " public key from mapping file: " + keyFile.getAbsolutePath());
            System.out.println("//////////////////////////////////////////////");
            System.out.println( pubKey );
            System.out.println("");
            System.out.println("");
            
        }
        else if( mappingPreference.equals( "database" ) )
        {
            ResultSet rs = query( pubKeyQuery + extOrg + "';" );
            rs.next();
            String keyString = rs.getString( 1 );
            byte[] keyBytes = keyString.getBytes();
            byte[] decodedKeyBytes = org.globus.util.Base64.decode( keyBytes );
            
            ByteArrayInputStream bais = new ByteArrayInputStream( decodedKeyBytes );
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
 
            X509Certificate cert1 = (X509Certificate)cf.generateCertificate( bais );
            
            pubKey = (RSAPublicKey)cert1.getPublicKey();
            bais.close();
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Extracted " + extOrg + " public key from mapping table in " + facility + " database");
            System.out.println("//////////////////////////////////////////////");
            System.out.println( pubKey );
            System.out.println("");
            System.out.println("");
            
        }
        else
        {
            throw new GeneralSecurityException( "Invalid mapping preference in configuration file" );
        }
        return pubKey;
    }
    
    /** This method is used to create a new mapped authorisation token for a user.  The token contains
     * the user's attributes and is digitally signed.
     *@param String proxyCertString Proxy certificate of the user.  The user's DN is extracted from this.
     *@param String extToken Original authorisation token from which a mapped one will be created.
     *@exception java.lang.Exception
     *@return org.jdom.Document the token is returned as a JDOM Document.
     */    
    private Document createMappedAuthorisationToken( String proxyCertString, org.w3c.dom.Element extToken ) throws Exception
    {

        String version = this.version;
        String provenance = "mapped";

        userDn = this.getUserDn(proxyCertString);

        //TokenReader reader = new TokenReader();
        //uk.ac.cclrc.authorisation.AttributeList list =  reader.getAttributes( extToken );
        //uk.ac.cclrc.authorisation.AttributeList list =  reader.getACInfo( extToken );
        //String acInfoString = list.getAcInfoAsXMLString();
        /*
        org.w3c.dom.Element acInfoElement = list.getAcInfoAsW3CElement();

        org.w3c.dom.Node sigNode = extToken.getLastChild();

        String sigString = ((org.w3c.dom.Element)sigNode).getLastChild().getFirstChild().getNodeValue();
        */
        //String extOrg = this.getOrgFromExtToken( extToken );
        /*
        PublicKey extPK = getPublicKey( extOrg );
        byte[] decodedSigString = org.globus.util.Base64.decode(sigString.getBytes());
        Signature sigVerifier = Signature.getInstance( digestAlgorithm + "with" + signatureAlgorithm );
        sigVerifier.initVerify( extPK );
        sigVerifier.update(acInfoElement.toString().getBytes());

        boolean trueSignature = sigVerifier.verify(decodedSigString);

        if( !trueSignature )
        {
            throw new Exception( "Signature on authorisation token is not valid." +
            "  It has not been produced from the private key of the trusted host." );
        }
       */

        // Put user DN from proxy certificate into same format as external database / external token
        // to allow comparison with the user DN from the external token
        String extOrg = list.getIssuerName();

        System.out.println("**********************************************");
        System.out.println("Extracted organisation from external token");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( extOrg );
        System.out.println("");
        System.out.println("");

        String extdbDNstartValue = prop.getProperty(extOrg+"_db_DN_start_value");
        if( extdbDNstartValue == null )
        {
            throw new GeneralSecurityException( "The first field of " + extOrg + " distinguished names is not specified in the config file" );
        }
        if( !( extdbDNstartValue.equalsIgnoreCase( "CN" ) || extdbDNstartValue.equalsIgnoreCase( "C" ) ) )
        {
            throw new GeneralSecurityException( "The first field of " + extOrg + " distinguished names specified in the config file must be C or CN" );
        }
        
        String quotedExtDBDNequalityString = prop.getProperty(extOrg+"_db_DN_equality_string");
        if( quotedExtDBDNequalityString == null )
        {
            throw new GeneralSecurityException( "The " + extOrg + " distinguished names equality string is not specified in the config file" );
        }                
        sf.setNewString( quotedExtDBDNequalityString );
        String extdbDNequalityString = sf.removeQuotes();            

        String quotedExtDBDNdelimString = prop.getProperty(extOrg+"_db_DN_delim_string"); 
        if( quotedExtDBDNdelimString == null )
        {
            throw new GeneralSecurityException( "The " + extOrg + " distinguished names delimiter string is not specified in the config file" );
        }                        
        sf.setNewString( quotedExtDBDNdelimString );
        String extdbDNdelimString = sf.removeQuotes();     

        sf.setNewString( userDn );
        sf.setDNConfig( extdbDNstartValue, extdbDNequalityString, extdbDNdelimString );
        String extFormatProxyDn = sf.formatDN();

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Taken the proxy certificate user DN and generated a user DN in the external organisation's (" + extOrg + ") format");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( extFormatProxyDn );
        System.out.println("");
        System.out.println("");

        // Gets the user DN from the authorisation token
        String extTokenDN = list.getHolder();

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Extracted user DN from authorisation token.");
        System.out.println( "If the authorisation token and proxy certificate are from the same person, the DNs should be the same." );
        System.out.println("//////////////////////////////////////////////");
        System.out.println( extTokenDN );
        System.out.println("");
        System.out.println("");

        boolean dnsSame = extFormatProxyDn.equals( extTokenDN );
        if( !dnsSame )
        {
            throw new InvalidAuthorisationTokenException( "proxy certificate DN and authorisation token DN do not match");
        }

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Compare the user DN from the proxy certificate with" +
            " that from the authorisation token");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( dnsSame );
        System.out.println("");

        String issuerDn = this.getIssuerDn();

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Extracted issuer's DN from authorisation server's X509 certificate.");
        System.out.println("This will be included in the new authorisation token generated.");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( issuerDn );
        System.out.println("");
        System.out.println("");            

        String issuerName = this.facility;
        String signatureAlgorithm=this.signatureAlgorithm;
        String issuerSerialNumber=this.issuerSerialNumber;
        // Certificate Limitation is currently done with current time and maximum proxy validity. In future the request of
        // maximum time to be made via the web service and the Server check if the request does not exceed the proxy certificate validity

        int[] notBefore=  this.getCurrentTime();

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get current time to determine when user's new authorisation token is valid from");
        System.out.println("//////////////////////////////////////////////");
        for( int i = 0; i < notBefore.length; i++ )
        {
            System.out.println( notBefore[ i ] );
        }
        System.out.println("");
        System.out.println("");          

        int[] notAfter = this.getNotAfter(proxyCertString,tokenLifetime,notBefore);

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get token lifetime from config file and add to current time to determine expiry time of new token");
        System.out.println("//////////////////////////////////////////////");

        for( int i = 0; i < notAfter.length; i++ )
        {
            System.out.println( notAfter[ i ] );
        }
        System.out.println("");
        System.out.println("");            

        // Get Roles from external token and add quotes to all items in the list to allow
        // an SQL query to be constructed from them.
        HashSet unquotedRoles = list.getRoleSet();            

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Extracted roles from external token");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( unquotedRoles );
        System.out.println("");
        System.out.println("");            

        Iterator unquotedRolesIt = unquotedRoles.iterator();
        String firstRole = (String) unquotedRolesIt.next();
        StringBuffer roleString = new StringBuffer( firstRole );
        while( unquotedRolesIt.hasNext() )
        {
            String nextRole = (String) unquotedRolesIt.next();
            roleString.append( ", " );
            roleString.append( nextRole );
        }
        sf.setNewString( roleString.toString() );
        String roles = sf.addQuotesToList();

        HashSet roleHashSet = new HashSet();

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get mapping preference from config file");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( mappingPreference );
        System.out.println("");
        System.out.println("");

        if( mappingPreference.equals("database") )
        {
            ResultSet rs = query(mappedRolesQuery1 + extOrg + mappedRolesQuery2 + roles + ");" ); // Nov 04
            
            while( rs.next() )
            {
                roleHashSet.add( rs.getString(1) );
            }

            try{

                rs.close();
                rs = null;                
                stat.close();
                stat = null;                
                conn.close();
                conn = null;
            }
            finally {
                // Always make sure result sets and statements are closed,

                if (rs != null) {
                    try { rs.close(); } catch (SQLException e) { ; }
                    rs = null;
                }
                if (stat != null) {
                    try { stat.close(); } catch (SQLException e) { ; }
                    stat = null;
                }
                if (conn != null) {
                    try { conn.close(); } catch (SQLException e) {
                        log.warn("Connection unable to be closed",e);  }
                    conn = null;
                }
            }
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Get mapped user roles from database");
            System.out.println("//////////////////////////////////////////////");
            System.out.println( roleHashSet );
            System.out.println("");
            System.out.println("");               

            if( roleHashSet.isEmpty() )
            {
                System.out.println("**********************************************");
                System.out.println("There are no mapped user roles in the database so a " +
                    "mapped attribute certificate can not be created.");
                System.out.println("//////////////////////////////////////////////");
                System.out.println("");
                System.out.println("");               

                return null;
            }

        }
        //else if( mappingPreference.equals( "file" ) )
        else
        {
/*
            mappedRoles = this.getMappedRolesFromMapFile( unquotedRoles, extOrg );
            Iterator mappedRolesIt = mappedRoles.iterator();
            while( mappedRolesIt.hasNext() )
            {
                roleHashSet.add( (String) mappedRolesIt.next() );
            }
*/
            roleHashSet = this.getMappedRolesFromMapFile( unquotedRoles, extOrg );

            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Get mapped user roles from file");
            System.out.println("//////////////////////////////////////////////");
            System.out.println( roleHashSet );
            System.out.println(  );
            System.out.println("");
            System.out.println("");               

            if( roleHashSet.isEmpty() )
            {
                System.out.println("**********************************************");
                System.out.println("There are no mapped user roles in the mapping file so a " +
                    "mapped attribute certificate can not be created.");
                System.out.println("//////////////////////////////////////////////");
                System.out.println("");
                System.out.println("");                                   

                return null;
            }                
        }
        /*
        else
        {
            throw new GeneralSecurityException( "mapping preference in properties file must be given value 'file' or 'database'" );
        }
       */
        AttributeList acInfo = new AttributeList(version, userDn, issuerDn,issuerName, issuerSerialNumber,notBefore,notAfter,roleHashSet, provenance);

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Create attribute list for user.  This comprises all non-signature information that will go into the user's authorisation token");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");              

        ACGen acGen = new ACGen();
        Document acDocument = acGen.sign( acInfo );
        //Document ACDocument = signAttributeListToGetToken( acInfo );
        return acDocument;
    }
    
    // NOT CURRENTLY USED
    /*
    private Document signAttributeListToGetToken( AttributeList attList ) throws Exception
    {
        ACGen acGen = new ACGen();
        
        Document signedAttList = acGen.sign( attList );
        
        return signedAttList;
      */  
        //Send for signing
/*
        XMLOutputter outputter = new XMLOutputter();
        String acInfoString = outputter.outputString(acInfoElement);

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get user's access control info from attribute list");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( acInfoString );
        System.out.println("");
        System.out.println("");              

        String signatureString = "";
        String digestString = "";
        
        try
        {
            ACGen acGen = new ACGen();
            digestString = acGen.getDigestString(acInfoString);
            
            signatureString = acGen.getSignatureString(acInfoString);
        }
        catch( Exception e )
        {
            log.error("Unable to generate digest/signature from attribute list",e);
            throw e;            
        }
        
        //create XML document out of it

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Generate digest from user's access control info");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( digestString );
        System.out.println("");
        System.out.println("");                
        
        
        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Generate digital signature from user's access control info using authorisation server's private key");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( signatureString );
        System.out.println("");
        System.out.println("");                

        Document ACDocument = new Document();
        Element root = new Element("attributeCertificate");

        ACDocument.setRootElement(root);
        root.addContent(acInfoElement);

        Element signatureElement = new Element("Signature",signatureURL);
        root.addContent(signatureElement);
        Namespace sigNS = signatureElement.getNamespace();
        
        Element signedInfoElement = new Element("SignedInfo",sigNS);
        Element signatureValueElement = new Element("SignatureValue",sigNS);
        signatureElement.addContent(signedInfoElement);
        signatureElement.addContent(signatureValueElement);
        
        Element canonElement = new Element("CanonicalizationMethod",sigNS);
        Element signatureMethodElement = new Element("SignatureMethod",sigNS);
        Element referenceElement = new Element("Reference",sigNS);
        signedInfoElement.addContent(canonElement);
        signedInfoElement.addContent(signatureMethodElement);
        signedInfoElement.addContent(referenceElement);
        
        Attribute canonAtt = new Attribute( "Algorithm", canonURL, Attribute.IDREF_ATTRIBUTE );
        canonElement.setAttribute( canonAtt );
        canonElement.setText( canonicalization );
        
        Attribute sigMethodAtt = new Attribute( "Algorithm", sigMethodURL, Attribute.IDREF_ATTRIBUTE );
        signatureMethodElement.setAttribute( sigMethodAtt );
        signatureMethodElement.setText( signatureAlgorithm );
        
        Attribute referenceAtt = new Attribute( "URI", referenceURL, Attribute.IDREF_ATTRIBUTE );
        referenceElement.setAttribute( referenceAtt );
        
        Element digestMethodElement = new Element("DigestMethod",sigNS);
        Element digestValueElement = new Element("DigestValue",sigNS);
        referenceElement.addContent(digestMethodElement);
        referenceElement.addContent(digestValueElement);

        Attribute digMethodAtt = new Attribute( "Algorithm", digestURL, Attribute.IDREF_ATTRIBUTE );
        digestMethodElement.setAttribute( digMethodAtt );
        digestMethodElement.setText( digestAlgorithm );
        
        digestValueElement.setText(digestString);
        signatureValueElement.setText(signatureString);
        
        
        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Put digital signature and user's access control info together to form the user's new authorisation token");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( outputter.outputString(root) );
        System.out.println("");
        System.out.println(""); 
 
        return ACDocument;               
  */          
        
//    }
    
    // NO LONGER USED
    /*
    private ResultSet getMappedRolesFromDB( String roles, String extOrg ) throws Exception
    {
        ResultSet rs = query(mappedRolesQuery1 + extOrg + mappedRolesQuery2 + roles + ");" ); // Nov 04
        return rs;        
    }
     */
    
    /** This takes an external set of roles that the user holds with another data centre and checks the mapping file to see
     * which internal role(s) these map to (if any).
     *@param java.util.HashSet roleHashSet the set of external roles
     *@param String extOrg The name of the external data centre that the user currently hols roles with
     *@exception java.lang.Exception
     *@return java.util.HashSet the local roles that the user is given via the trust agreement
     */    
    private HashSet getMappedRolesFromMapFile( HashSet roleHashSet, String extOrg ) throws Exception
    {
        HashSet localRoles = new HashSet();
        Iterator roleHashSetIt = roleHashSet.iterator();
        
        // Look at each trusted element of the map file.  Where the name matches that of the ext org
        // iterate through the roles array above and for each element, compare it against each of the
        // 'remote' attributes to see whether there is a match.  Where there is a match, get the name
        // of the corresponding local attribute.
        SAXBuilder saxb = new SAXBuilder();
        org.jdom.Document mapFileDoc = saxb.build( mapFilePath );
        Element root = mapFileDoc.getRootElement();
        List trustedElements = root.getChildren("trusted");
        Element trustedElement = null;
        for( int i = 0; i < trustedElements.size(); i++ )
        {
            trustedElement = (Element)trustedElements.get( i );
            String trustedAttValue = trustedElement.getAttributeValue("name");
            if( trustedAttValue.equals( extOrg ) )
            {
                List roleElements = trustedElement.getChildren("role");
                Element roleElement = null;
                //for( int k = 0; k < roleArray.length; k++ )
                while( roleHashSetIt.hasNext() )
                {
                    String role = (String) roleHashSetIt.next();
                    for( int j = 0; j < roleElements.size(); j++ )
                    {
                        roleElement = (Element)roleElements.get( j );
                        String roleAttValue = roleElement.getAttributeValue("remote");
                        if( role.equals( roleAttValue ) )
                        {
                            String localRole = roleElement.getAttributeValue("local");
                            localRoles.add( localRole );
                        }
                    }
                }
            }
        }

        return localRoles;
    }
    
    // NOT CURRENTLY USED
    private HashSet getRolesFromExtToken( org.w3c.dom.Element extToken ) throws Exception
    {
        HashSet roleHashSet = list.getRoleSet();            

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Extracted roles from external token");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( roleHashSet );
        System.out.println("");
        System.out.println("");
        
        return roleHashSet;
    }

    // NOT CURRENTLY USED
    private String getOrgFromExtToken( org.w3c.dom.Element extToken ) throws Exception
    {
        String extOrg = "";
        
        //TokenReader reader = new TokenReader();
        //uk.ac.cclrc.authorisation.AttributeList list =  reader.getAttributes( extToken );        
        //uk.ac.cclrc.authorisation.AttributeList list =  reader.getACInfo( extToken );        
        extOrg = list.getIssuerName();

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Extracted organisation from external token");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( extOrg );
        System.out.println("");
        System.out.println("");
        
        return extOrg;
    }
    
    
    /** This method is used to create a new original authorisation token for a user.  The token contains
     * the user's attributes and is digitally signed.
     *@param String proxyCertString Proxy certificate of the user.  The user's DN is extracted from this.
     * The DN is used to search for the user's role(s) in the database - these are included in the token.
     *@exception java.lang.Exception
     *@return org.jdom.Document the token is returned as a JDOM Document.
     */
    private Document createAuthorisationToken(String proxyCertString) throws Exception{
        //Create authorisation Token
        
        String version = this.version;
        String provenance = "original";

        // Format user DN to allow for searching of permissions from database later
        /*
        String userDn = this.getUserDn(proxyCertString);            
        sf.setNewString( userDn );
        sf.setDNConfig( dbDNstartValue, dbDNequalityString, dbDNdelimString );
        userDn = sf.formatDN();
*/
        String issuerDn = this.getIssuerDn();

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Extracted issuer's DN from authorisation server's X509 certificate");
        System.out.println("This will be included in the new authorisation token generated.");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( issuerDn );
        System.out.println("");
        System.out.println("");            

        String issuerName = this.facility;
        String signatureAlgorithm=this.signatureAlgorithm;
        String issuerSerialNumber=this.issuerSerialNumber;
        // Certificate Limitation is currently done with current time and maximum proxy validity. In future the request of
        // maximum time to be made via the web service and the Server check if the request does not exceed the proxy certificate validity

        int[] notBefore=  this.getCurrentTime();

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get current time to determine when user's authorisation token is valid from");
        System.out.println("//////////////////////////////////////////////");
        for( int i = 0; i < notBefore.length; i++ )
        {
            System.out.println( notBefore[ i ] );
        }
        System.out.println("");
        System.out.println("");          

        int[] notAfter = this.getNotAfter(proxyCertString,tokenLifetime,notBefore);

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get token lifetime from config file and add to current time to determine expiry time of new token");
        System.out.println("//////////////////////////////////////////////");
        for( int i = 0; i < notAfter.length; i++ )
        {
            System.out.println( notAfter[ i ] );
        }
        System.out.println("");
        System.out.println("");            

        ResultSet rs = query(stdRolesQuery + userDn + "'"); // Nov 04
        
        HashSet roleHashSet = new HashSet();            
        while( rs.next() )
        {
            roleHashSet.add( rs.getString(1) );
        }

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get roles from database for the user with the above DN");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( roleHashSet );
        System.out.println("");
        System.out.println("");               

        if( roleHashSet.isEmpty() )
        {
            return null;
        }
        
        try{

            rs.close();
            rs = null;                
            stat.close();
            stat = null;                
            conn.close();
            conn = null;
        }
        finally {
            // Always make sure result sets and statements are closed,

            if (rs != null) {
                try { rs.close(); } catch (SQLException e) { ; }
                rs = null;
            }
            if (stat != null) {
                try { stat.close(); } catch (SQLException e) { ; }
                stat = null;
            }
            if (conn != null) {
                try { conn.close(); } catch (SQLException e) {
                    log.warn("Connection unable to be closed",e);  }
                conn = null;
            }
        }

        AttributeList acInfo = new AttributeList(version, userDn, issuerDn,issuerName,issuerSerialNumber,notBefore,notAfter,roleHashSet,provenance);

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Create attribute list for user.  This comprises all non-signature information that will go into the user's authorisation token");
        System.out.println("//////////////////////////////////////////////");
        System.out.println("");
        System.out.println("");              

        ACGen acGen = new ACGen();
        Document acDocument = acGen.sign( acInfo );
        //Document ACDocument = signAttributeListToGetToken( acInfo );

        return acDocument;
    }
    
    /** This method is used to search the database for the user.  This search is done by user DN.
     *@param String proxyCert Proxy certificate of the user.  The user's DN is extracted from this.
     *@exception java.lang.Exception
     *@exception java.lang.ClassNotFoundException
     *@exception java.sql.SQLException
     *@return boolean true/false indicates whether user was found in database or not.
     */
    public boolean searchDBForUser( String proxyCert ) throws ClassNotFoundException, SQLException, Exception
    {
        boolean userPresent = false;
    
        userDn = this.getUserDn( proxyCert );
        
        System.out.println("**********************************************");
        System.out.println("User DN extracted from user's proxy certificate");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( userDn );
        System.out.println("");

        sf.setNewString( userDn );
        sf.setDNConfig( dbDNstartValue, dbDNequalityString, dbDNdelimString );
        userDn = sf.formatDN();
        
        System.out.println("**********************************************");
        System.out.println("Formatted the user DN to allow searching for the user in the database");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( userDn );
        System.out.println("");
        System.out.println("");        
        
        ResultSet rs = query(userQuery + userDn + "'"); // Nov 04
        userPresent = rs.next();

        return userPresent;
    }
    
    // NOT CURRENTLY USED
    /*
    private ResultSet getUserPrivilegesFromDB(String userDn) throws ClassNotFoundException,SQLException ,Exception{
        
        ResultSet rs = query(stdRolesQuery + userDn + "'"); // Nov 04
     */
/*
        if(rs.next()){
*/
    /*      rs.next();
            return rs;
     */
            /*
        }
        else
        {
            //log.warn("DN "+userDn +" not in database.");
            //return rs;
            throw new GeneralSecurityException( "User " + userDn + " has no roles in the database" );
        }
             */
            
 //   }
   
    /** This method is used to submit queries to the database.
     *@param String expression The SQL statement to be executed
     *@exception java.lang.Exception
     *@return java.sql.ResultSet this is the result of the SQL query
     */        
    public synchronized ResultSet query(String expression) throws Exception
    {
        try
        {
            Class.forName(dbDriverClass); // Nov 04
            if( userName == null || password == null )
            {
                conn = DriverManager.getConnection(dbDriverString+"//"+server+":"+ port+"/"+dbName); // Nov 04
            }
            else
            {
                conn = DriverManager.getConnection(dbDriverString+"//"+server+":"+ port+"/"+dbName, userName, password ); // Nov 04
            }
            stat = conn.createStatement();
            ResultSet rs = stat.executeQuery(expression);       // run the query
            return rs;
        }
        catch (ClassNotFoundException e) {
            log.error(e);
            throw e; // need to modify it
        }catch (SQLException e) {
            log.error(e);
            throw e; // need to modify it
        }
        catch (Exception e) {
            log.error(e);
            throw e; // need to modify it
        }
    }
    public void saveToDb(){
    }
    
    /** Method to get UserDn from user's Proxy Certificate
     *@param String roles a comma-separated list of local roles that are needed to access a given dataset at this data centre
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */        
    private String getUserDn(String proxyCertString) throws Exception{
        
        GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(proxyCertString.getBytes()));
        //return globusCredential.getSubject();
        //System.out.println(globusCredential.getIdentityCertificate().getSubjectDN().toString());

        GSSCredential userCredential = null;
        
        try
        {
            userCredential = new GlobusGSSCredentialImpl(globusCredential,GSSCredential.INITIATE_AND_ACCEPT);
        }
        catch( Exception e )
        {
            System.out.println("**********************************************");
            System.out.println("The user's proxy certificate is invalid meaning that a DN can not be extracted");
            System.out.println("//////////////////////////////////////////////");
            System.out.println("");
            System.out.println("");
            log.error( "The user's proxy certificate is invalid meaning that a DN can not be extracted", e );
            throw e;
        }
        //user globus dns for User dn
        //X509Certificate cert = globusCredential.getIdentityCertificate();
        // System.out.println(cert.getSubjectDN().toString());
        //return cert.getSubjectDN().toString();

        return userCredential.getName().toString();
        //return userCredential.getName().toString();
        /* for test
                    FileReader fileReader = new FileReader("/home/asm67/project/authorisation/certificates/test.cred");
        BufferedReader in = new BufferedReader(fileReader);
        String inputLine;
        StringBuffer cert= new StringBuffer();
        while ((inputLine = in.readLine()) !=null) {
            cert.append(inputLine);
            cert.append("\n");
        }
        in.close();
        String certificate=cert.toString();
         uk.ac.cclrc.authorisation.
        GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(certificate.getBytes()));
        //return globusCredential.getSubject();
        System.out.println(globusCredential.getIdentityCertificate().getSubjectDN().toString());

        GSSCredential userCredential = new GlobusGSSCredentialImpl(globusCredential,GSSCredential.INITIATE_AND_ACCEPT);
        return userCredential.getName().toString();
         */
            
    }
    
    /** This method is the authorisation Server's DN.
     *@exception java.io.IOException
     *@exception java.security.InvalidKeyException
     *@exception java.security.GeneralSecurityException
     *@return String the DN is returned as a String
     */        
    private String getIssuerDn() throws IOException, GeneralSecurityException, InvalidKeyException{
        //Load Host's Certificate.
        // currently hard coded... change it
        // X509Certificate hostCertificate= CertUtil.loadCertificate(certFile.trim());
        //return hostCertificate.getSubjectDN().toString();
        
        //Using SUN Java Key Store for now
        String keyStoreFileName = prop.getProperty("keystore");
        String keyStorePasswd = prop.getProperty("keystore_passwd");
        String keyStoreAlias = prop.getProperty("keystore_alias");
        String keyStoreType = prop.getProperty("keystore_type");        
        if( keyStoreType == null )
        {
            throw new GeneralSecurityException( "The type of keystore is not specified in the config file" );
        }                
        
        if( keyStoreAlias == null )
        {
            throw new GeneralSecurityException( "The keystore alias is not specified in the config file" );
        }        
        
        if( keyStoreFileName == null || keyStoreFileName.equals("") )
        {
            throw new GeneralSecurityException( "The keystore file name is not specified in the config file" );
        }
        // System.out.println(keyStoreFileName);
        //if(keyStoreFileName == null || keyStoreFileName.equals("")) keyStoreFileName = System.getProperty("user.home")+File.separator+".keystore";
        //if(keyStorePasswd == null || keyStorePasswd.equals("")) keyStorePasswd = "changeit";
        if(keyStorePasswd == null || keyStorePasswd.equals(""))
        {
            throw new GeneralSecurityException( "The keystore password is not specified in the config file" );
        }    
        
        //KeyStore keystore = KeyStore.getInstance( "JKS" );
        KeyStore keystore = KeyStore.getInstance( keyStoreType );
        keystore.load(new FileInputStream(keyStoreFileName), keyStorePasswd.toCharArray());
        
        java.security.cert.X509Certificate cert = (X509Certificate)keystore.getCertificate(keyStoreAlias);
        
        if( cert == null )
        {
            throw new GeneralSecurityException( "The key store alias specified in the config file is not valid" );
        }
        
        return cert.getIssuerDN().toString();
    }
    
    
    /** This method is used to find out who this data centre's trusted hosts are from the database.
     * It does not take into account which individual role mappings a user may need to access a given dataset
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */    
    public HashSet getTrustedHostsFromDB() throws Exception
    {

        ResultSet rs = query( affilOrgsQuery ); // Nov 04
        HashSet affilOrgs = new HashSet();
        while( rs.next() )
        {
            String nextOrg = rs.getString( 1 );
            affilOrgs.add( nextOrg );
        }

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get a list of organisations from DB who have a bilateral trust agreement with this one.");
        System.out.println("If the user's current authorisation token is not accepted," +
            " they should use an original token from an organisation in this list if possible.");
        System.out.println("//////////////////////////////////////////////");           

        return affilOrgs;        
        
    }

    /** This method is used to find out who this data centre's trusted hosts are from the mapping file.
     * It takes into account which individual role mappings a user needs to access a given dataset
     *@param String roles a comma-separated list of local roles that are needed to access a given dataset at this data centre
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */        
    public HashSet getTrustedHostsFromMapFile( String roles ) throws Exception
    {
        String[] roleArray = roles.split( ",");
        HashSet trustedHosts = new HashSet();
        
        SAXBuilder saxb = new SAXBuilder();
        org.jdom.Document mapFileDoc = saxb.build( mapFilePath );
        Element root = mapFileDoc.getRootElement();
        List trustedElements = root.getChildren("trusted");
        Element trustedElement = null;
        for( int i = 0; i < trustedElements.size(); i++ )
        {
            trustedElement = (Element)trustedElements.get( i );
            String trustedAttValue = trustedElement.getAttributeValue("name");
            List roleElements = trustedElement.getChildren("role");
            Element roleElement = null;
            for( int k = 0; k < roleArray.length; k++ )
            {
                for( int j = 0; j < roleElements.size(); j++ )
                {
                    roleElement = (Element)roleElements.get( j );
                    String roleAttValue = roleElement.getAttributeValue("local");
                    if( roleArray[ k ].equals( roleAttValue ) )
                    {
                        trustedHosts.add( trustedAttValue );
                        break;
                    }
                }
            }
            
        }
        
        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Got trusted hosts from map file based on local roles required");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( trustedHosts );
        System.out.println("");
        System.out.println("");
        
        
        return trustedHosts;
    }

    /** This method is used to find out who this data centre's trusted hosts are from the mapping file.
     * It does not take into account which individual role mappings a user may need to access a given dataset
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */        
    public HashSet getTrustedHostsFromMapFile() throws Exception
    {
        HashSet trustedHosts = new HashSet();
        
        SAXBuilder saxb = new SAXBuilder();
        org.jdom.Document mapFileDoc = saxb.build( mapFilePath );
        Element root = mapFileDoc.getRootElement();
        List trustedElements = root.getChildren("trusted");
        Element trustedElement = null;
        
        for( int i = 0; i < trustedElements.size(); i++ )
        {
            trustedElement = (Element)trustedElements.get( i );
            String trustedAttValue = trustedElement.getAttributeValue("name");
            trustedHosts.add( trustedAttValue );
        }
        
        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Get a list of organisations from map file who have a bilateral trust agreement with this one.");
        System.out.println("If the user's current authorisation token is not accepted," +
            " they should use an original token from an organisation in this list if possible.");
        System.out.println("//////////////////////////////////////////////");           
        
        return trustedHosts;
    }
    
    /** This method is used to find out who this data centre's trusted hosts are from the database.
     * It takes into account which individual role mappings a user needs to access a given dataset
     *@param String roles a comma-separated list of local roles that are needed to access a given dataset at this data centre
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */    
    public HashSet getTrustedHostsFromDB( String roles ) throws Exception
    {
        ResultSet rs = query( affilOrgsQuery2 + roles + ");" ); // Nov 04
        HashSet affilOrgs = new HashSet();
        while( rs.next() )
        {
            String nextOrg = rs.getString( 1 );
            affilOrgs.add( nextOrg );
        }

        // NDB - demo-code
        System.out.println("**********************************************");
        System.out.println("Got trusted hosts from DB based on local roles required");
        System.out.println("//////////////////////////////////////////////");
        System.out.println( affilOrgs );
        System.out.println("");
        System.out.println("");

        return affilOrgs;        
    }
    
   
    
    /** Method to get the current time expressed as an array of int's
     *@return int[] The time is returned as an array of int's in the following order: 
     * year, month, date, hour of day, minute, second
     */    
    private int[] getCurrentTime() {
        GregorianCalendar calendar = new GregorianCalendar();
        int[] time = new int[6];
        time[0]= calendar.get(Calendar.YEAR);
        time[1]= calendar.get(Calendar.MONTH);
        time[2]= calendar.get(Calendar.DATE);
        time[3]= calendar.get(Calendar.HOUR_OF_DAY);
        time[4]= calendar.get(Calendar.MINUTE);
        time[5]= calendar.get(Calendar.SECOND);
        return time;
        
    }

    /** Method to get expiry time of the Attribute Certificate based on the current time plus the lesser of the lifetime of the proxy certificate
     ** and the lifetime specified in the config file.
     *@param String proxyCertString Proxy certificate of the user.
     *@param String tokenLifetime The maximum lifetime of the token specified in the config file.
     *@param int[] time The current time expressed as an array of int's in the following order:
     * year, month, date, hour_of_day, minute, second
     *@exception java.lang.Exception
     *@return int[] the expiry time of the token
     */        
    private int[] getNotAfter(String proxyCertString,String tokenLifetime,int[] time) throws Exception {
        GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(proxyCertString.getBytes()));
        GSSCredential userCredential = new GlobusGSSCredentialImpl(globusCredential,GSSCredential.INITIATE_AND_ACCEPT);
        int remainingTime = userCredential.getRemainingLifetime(); //time is seconds left
        
        if(remainingTime == 0) throw new GeneralSecurityException("Proxy certificate has timed out");
        GregorianCalendar notAfterCal = new GregorianCalendar(time[0],time[1],time[2],time[3],time[4],time[5]);        
        
        int lifetime = remainingTime;
        
        if( tokenLifetime.length() == 8 )
        {
            int days = 0;
            int hours = 0;
            int minutes = 0;

            try
            {
                String dayString = tokenLifetime.substring( 0, 2 );
                days = Integer.parseInt( dayString );

                String hourString = tokenLifetime.substring( 3, 5 );
                hours = Integer.parseInt( hourString );

                String minuteString = tokenLifetime.substring( 6, 8 );
                minutes = Integer.parseInt( minuteString );
                
                if( days >= 0 && hours >= 0 && hours < 24 && minutes > 0 && minutes < 60 )
                {
                    lifetime = ( minutes * 60 ) + ( hours * 60 * 60 ) + ( days * 60 * 60 * 24 ); // in seconds

                    if( remainingTime < lifetime )
                    {
                        lifetime = remainingTime;
                    }            
                }
            }
            catch( Exception e )
            {
                log.error("Lifetime of authorisation token not specified in config file correctly so default used instead; " +
                    "the lifetime of the token has been set to the remaining lifetime of the proxy certificate.",e);
                //throw e;
            }
        }

        notAfterCal.add( Calendar.SECOND, lifetime );
        int[] notAfter = new int[6];
        notAfter[0]= notAfterCal.get(Calendar.YEAR);
        notAfter[1]= notAfterCal.get(Calendar.MONTH);
        notAfter[2]= notAfterCal.get(Calendar.DATE);
        notAfter[3]= notAfterCal.get(Calendar.HOUR_OF_DAY);
        notAfter[4]= notAfterCal.get(Calendar.MINUTE);
        notAfter[5]= notAfterCal.get(Calendar.SECOND);
        return notAfter;
    }
    
    
    /* private void loadKeyStore() throws IOException, GeneralSecurityException{
     
        Properties prop = new Properties();
        try{
            prop.load(new FileInputStream(Config.getContextPath()+"authorisation.prop"));
        }
        catch(IOException ioe){
            log.error("Unable to find "+Config.getContextPath()+"authorisation.prop",ioe);
            throw ioe;
        }
     
     
        //String keyStoreFileName = System.getProperty("user.home")+File.separator+".keystore";
        String keyStoreFileName = prop.getProperty("keystore");
        String keyStorePasswd = prop.getProperty("keystore_passwd");
        String keyStoreAlias = prop.getProperty("keystore_alias");
        algorithm = prop.getProperty("algorithm");
        // System.out.println(keyStoreFileName);
        if(keyStoreFileName == null || keyStoreFileName.equals("")) keyStoreFileName = System.getProperty("user.home")+File.separator+".keystore";
        if(keyStorePasswd == null || keyStorePasswd.equals("")) keyStorePasswd = "changeit";
     
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keyStoreFileName), keyStorePasswd.toCharArray());
        Key key = keystore.getKey(keyStoreAlias, keyStorePasswd.toCharArray());
        if(key == null)throw new GeneralSecurityException("No private key loaded");
        prvKey = (RSAPrivateKey)key;
        java.security.cert.Certificate cert = keystore.getCertificate(keyStoreAlias);
        if(key == null)throw new GeneralSecurityException("No certificate loaded");
        pubKey = (RSAPublicKey)cert.getPublicKey();
    }
     */
    
    /* test */
    public static void main(String arg[]){
        
    }
    
    
}
