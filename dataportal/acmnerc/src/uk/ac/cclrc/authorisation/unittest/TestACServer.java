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
import ac.dl.xml.*;
import org.globus.util.Base64;


/*import org.globus.gsi.*;
import org.globus.gsi.gssapi.*;
import java.net.*;
import org.ietf.jgss.*;
import java.io.*;*/
/**
 *
 *
 * @author  gjd37
 */
public class TestACServer {
    
    /** Creates a new instance of ACServertTest */
    public TestACServer(String[] args) {
        
        try {
            ACServer acs= new ACServer();
            
            //load in cert
            // URL url1 = new URL("file:///c:/cred.au3"); NDB
            URL url1 = new URL("file:///D:/Neil/x509up_u_ndb23");
            //http://dmgdev1.esc.rl.ac.uk:9080/sessionmanager/services/SessionManager      // System.out.println(url);
            URLConnection con = url1.openConnection();
            InputStream in2 = con.getInputStream();
            BufferedReader in = new BufferedReader(new InputStreamReader(in2));
            String inputLine;
            // String certt;
            StringBuffer cert = new StringBuffer();
            while ((inputLine = in.readLine()) != null){
                //  System.out.println(inputLine);
                cert.append(inputLine);
                cert.append("\n");
                // if(!inputLine.equals("-----END CERTIFICATE-----"))  cert.append("\n");
                
            }
            in.close();
            String cert3 = cert.toString();
            
            //System.out.println(acs.getUserDn("aa"));
            //System.out.println(acs.getUserDn(cert3));
            //System.out.println(acs.getAuthorisationTokenInXML(cert3));
            
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Loaded in user's proxy certificate file and extracted as string");
            System.out.println("//////////////////////////////////////////////");
            System.out.println( cert3 );
            System.out.println("");
            System.out.println("");
            
            org.w3c.dom.Element xml  = acs.getAuthorisationTokenInDOM(cert3);
            
            org.jdom.input.DOMBuilder buildert = new org.jdom.input.DOMBuilder();
            org.jdom.Element el = buildert.build(xml);
             Document d = new Document(el);
            Saver.save(d,new File("c:/ws.cred"));
            // System.out.println("Saved file to c:/xml.xml");
            
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Save user's new authorisation token in file 'ws.cred'");
            System.out.println("//////////////////////////////////////////////");
            System.out.println("");
            System.out.println("");                
            
            
            TokenReader reader = new TokenReader();
            org.w3c.dom.Document doc = Converter.JDOMtoDOM(d);
            org.w3c.dom.Element element = doc.getDocumentElement();
            
            
            //   org.w3c.dom.Document doc =XML_DOMBuilder.parse(new File("c:/xml.xml"));
            //   org.w3c.dom.Element element  = doc.getDocumentElement();
            
            
            //TokenReader reader = new TokenReader();
            
            uk.ac.cclrc.authorisation.AttributeList list =  reader.getAttributes(element);
            
            // cred = GlobusProxy.load(data,caCertLocation);
            
            // NDB - demo-code
            System.out.println("**********************************************");
            System.out.println("Read user's authorisation token file back in and get data access permissions from it");
            System.out.println("//////////////////////////////////////////////");
            //System.out.println( list.getDataAccessGroup() );
            System.out.println( list.getRoleSet() );
            System.out.println("");
            System.out.println("");   
            
            // System.out.println("Data access: "+list.getDataAccessGroup()); NDB
            // System.out.println("Wrapper access "+list.getWrapperGroup()); NDB
            // System.out.println("Meta access "+list.getDPView()); NDB

            
            
            System.out.println("**********************************************");
            System.out.println("Create a new authorisation token from the existing token and the mapping table");
            System.out.println("//////////////////////////////////////////////");
            System.out.println("");
            System.out.println("");   
            
            
            //getUserPrivilegesFromDB();
        } catch (Exception e){
            //System.out.println(e);
        }
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        
        new TestACServer(args);
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
