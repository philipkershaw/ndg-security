/*
 * ACServertTest.java
 *
 * Created on 11 November 2003, 15:26
 */

package uk.ac.cclrc.authorisation.unittest;
import java.net.*;
import uk.ac.cclrc.authorisation.client.*;
import java.io.*;
import uk.ac.cclrc.authorisation.server.*;
import org.jdom.*;
import org.jdom.input.*;
import org.jdom.output.*;
import ac.dl.xml.*;
import org.globus.util.Base64;
import java.util.*;

/**
 *
 *
 * @author  gjd37
 */
public class TestACServer_1 {
    
    /** Creates a new instance of ACServertTest */
    public TestACServer_1(String[] args) {
        
        try {
            ACServer acs= new ACServer();
            
            HashSet trustedHosts = null;
            /*
            trustedHosts = acs.getTrustedHostsFromDB();
            Iterator it = trustedHosts.iterator();
            while( it.hasNext() )
            {
                System.out.println( (String)it.next() );
            }

            trustedHosts = acs.getTrustedHostsFromMapFile();
            it = trustedHosts.iterator();
            while( it.hasNext() )
            {
                System.out.println( (String)it.next() );
            }
            */
            
            //load in cert
            //URL url1 = new URL("file:///D:/Neil/X509up_u_sas27");
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Loaded in user's proxy certificate file");
            System.out.println("//////////////////////////////////////////////");
            System.out.println("");
            System.out.println("");
            
       
            SAXBuilder saxb = new SAXBuilder();
            org.jdom.Document authTokenDoc = saxb.build("file:///C:/bodcAuthToken.cred");
            org.w3c.dom.Document domDoc = Converter.JDOMtoDOM( authTokenDoc );
            
            TokenReader reader = new TokenReader();
            org.w3c.dom.Element element = domDoc.getDocumentElement();
            
            uk.ac.cclrc.authorisation.AttributeList list =  reader.getACInfo( element );
            
            // cred = GlobusProxy.load(data,caCertLocation);
            
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Read user's authorisation token file back in and get roles from it");
            System.out.println("//////////////////////////////////////////////");
            System.out.println( list.getRoleSet() );
            System.out.println("");
            System.out.println("");   

/*            
            trustedHosts = acs.getTrustedHostsFromMapFile( "postdoc");
            trustedHosts = acs.getTrustedHostsFromDB( "'postdoc'");
*/            

        } catch (Exception e){
            e.printStackTrace();
        }
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        
        new TestACServer_1(args);
        //go();
    }
    
    public static void go() throws Exception{
        //GlobusCredential globusCredential = new GlobusCredential(new FileInputStream("c:/cred.au2"));
        //GSSCredential  cred = new GlobusGSSCredentialImpl(globusCredential, GSSCredential.INITIATE_AND_ACCEPT);
        //String credString = turnintoString(globusCredential);
        //System.out.println(credString);
        
    }
    
    /*static String turnintoString(GlobusCredential cred)throws Exception{
        
        
        
        File file = new File("c:/credsave.au2");
        FileOutputStream out = new FileOutputStream(file);
        
        cred.save(out);
        out.close();
        //turn proxy into string
        URL url1  = new URL("file:///"+file.getAbsolutePath());
        // System.out.println(url);
        URLConnection con = url1.openConnection();
        InputStream in2 = con.getInputStream();
        BufferedReader in = new BufferedReader(new InputStreamReader(in2));
        String inputLine;
        // String certt;
        StringBuffer cert = new StringBuffer();
        while ((inputLine = in.readLine()) != null){
            //System.out.println(inputLine);
            cert.append(inputLine);
            cert.append("\n");
            //  if(!inputLine.equals("-----END CERTIFICATE-----"))  cert.append("\n");
            
        }
        in.close();
        //end of file save
        
        
        file.delete();
        return cert.toString();
        
    }*/
    
    
    
    
}
