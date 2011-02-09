/*
 * ACWebService.java
 *
 * Created on July 18, 2003, 12:59 PM
 */

package uk.ac.cclrc.authorisation.server;

import org.globus.gsi.GlobusCredential;
import org.globus.gsi.gssapi.GlobusGSSCredentialImpl;
import java.util.*;
import org.apache.log4j.*;
import uk.ac.cclrc.authorisation.Config;
import java.sql.*;
/**
 * The web service class acts as an interface for external services to request for authorisation token. To request for
 * authorisation token the user has to forward his proxy certificate.
 * @author  asm67
 */
public class ACWebService {
    static Logger log = Logger.getLogger(ACWebService.class);
    /** This method is used to get authorisation Token describing the parameters of the user in XML string
     *@param String userCert proxyCertificate of the user in String
     *@exception java.lang.Exception
     *@return String XML string representation of the Authorizatino token for the user
     */
    public String getAuthorisationTokenInXMLString(String userCert) throws Exception {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try {
            
            ACServer acServer = new ACServer();
            
            return acServer.getAuthorisationTokenInXML(userCert);
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
    }
    
    /** This method is used to get authorisation Token describing the parameters of the user as a proxy certificate string
     *@param String userCert proxyCertificate of the user in String
     *@exception java.lang.Exception
     *@return org.w3c.dom.Element DOM Element representation of the Authorisation token for the user
     */
    public org.w3c.dom.Element getAuthorisationTokenInDOMElement(String userCert) throws Exception {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try {
            ACServer acServer = new ACServer();
                        /* GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(userCert.getBytes())
                        GSSCredential credential = new GlobusGSSCredentialImpl(globusCredential, GSSCredential.INITIATE_AND_ACCEPT);
                        userDn = credential.getName().toString();
                         */
            return acServer.getAuthorisationTokenInDOM(userCert);
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
    }
    
    /** This method is used to get authorisation Token describing the parameters of the user in XML string
     *@param String userCert proxyCertificate of the user in String
     *@param org.w3c.dom.Element extAuthToken external authorisation token
     *@exception java.lang.Exception
     *@return org.w3c.dom.Element DOM Element representation of the Authorisation token for the user
     */
    public org.w3c.dom.Element getAuthorisationTokenInDOMElement(String userCert, org.w3c.dom.Element extAuthToken) throws Exception {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try {
            ACServer acServer = new ACServer();
                        /* GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(userCert.getBytes())
                        GSSCredential credential = new GlobusGSSCredentialImpl(globusCredential, GSSCredential.INITIATE_AND_ACCEPT);
                        userDn = credential.getName().toString();
                         */
            return acServer.getAuthorisationTokenInDOM(userCert, extAuthToken);
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
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
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try {
            ACServer acServer = new ACServer();
                        /* GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(userCert.getBytes())
                        GSSCredential credential = new GlobusGSSCredentialImpl(globusCredential, GSSCredential.INITIATE_AND_ACCEPT);
                        userDn = credential.getName().toString();
                         */
            return acServer.searchDBForUser( proxyCert );
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
    }    
    
    /** This method is used to find out who this data centre's trusted hosts are from the database.
     * It does not take into account which individual role mappings a user may need to access a given dataset
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */    
    public HashSet getTrustedHostsFromDB() throws Exception
    {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try {
            ACServer acServer = new ACServer();
                        /* GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(userCert.getBytes())
                        GSSCredential credential = new GlobusGSSCredentialImpl(globusCredential, GSSCredential.INITIATE_AND_ACCEPT);
                        userDn = credential.getName().toString();
                         */
            return acServer.getTrustedHostsFromDB();
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
    }
    
    /** This method is used to find out who this data centre's trusted hosts are from the database.
     * It takes into account which individual role mappings a user needs to access a given dataset
     *@param String roles a comma-separated list of local roles that are needed to access a given dataset at this data centre
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */    
    public HashSet getTrustedHostsFromDB( String roles ) throws Exception
    {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try {
            ACServer acServer = new ACServer();
                        /* GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(userCert.getBytes())
                        GSSCredential credential = new GlobusGSSCredentialImpl(globusCredential, GSSCredential.INITIATE_AND_ACCEPT);
                        userDn = credential.getName().toString();
                         */
            return acServer.getTrustedHostsFromDB( roles );
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
    }
    
    /** This method is used to find out who this data centre's trusted hosts are from the mapping file.
     * It takes into account which individual role mappings a user needs to access a given dataset
     *@param String roles a comma-separated list of local roles that are needed to access a given dataset at this data centre
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */        
    public HashSet getTrustedHostsFromMapFile( String roles ) throws Exception
    {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try {
            ACServer acServer = new ACServer();
                        /* GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(userCert.getBytes())
                        GSSCredential credential = new GlobusGSSCredentialImpl(globusCredential, GSSCredential.INITIATE_AND_ACCEPT);
                        userDn = credential.getName().toString();
                         */
            return acServer.getTrustedHostsFromMapFile( roles );
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
            
    }
    
    /** This method is used to find out who this data centre's trusted hosts are from the mapping file.
     * It does not take into account which individual role mappings a user may need to access a given dataset
     *@exception java.lang.Exception
     *@return java.util.HashSet the list of trusted hosts
     */        
    public HashSet getTrustedHostsFromMapFile() throws Exception
    {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        
        try {
            ACServer acServer = new ACServer();
                        /* GlobusCredential globusCredential = new GlobusCredential(new ByteArrayInputStream(userCert.getBytes())
                        GSSCredential credential = new GlobusGSSCredentialImpl(globusCredential, GSSCredential.INITIATE_AND_ACCEPT);
                        userDn = credential.getName().toString();
                         */
            return acServer.getTrustedHostsFromMapFile();
        } catch (Exception e) {
            log.error(e);
            throw e;
        }
    }
                
}
