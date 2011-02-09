/*
 * TestWSServer.java
 *
 * Created on 13 November 2003, 16:09
 */

package uk.ac.cclrc.authorisation.unittest;
import org.apache.axis.AxisFault;
import javax.xml.rpc.ParameterMode;
import org.apache.axis.client.Call;
import org.apache.axis.encoding.XMLType;
import org.apache.axis.client.Service;
import javax.xml.namespace.QName;
import org.jdom.*;
import org.jdom.input.*;
import ac.dl.xml.*;
import java.net.*;
import java.io.*;
/**
 *
 * @author  gjd37
 */
public class TestWSServer {
    
    /** Creates a new instance of TestWSServer */
    public TestWSServer(String[] args) {
        try{
            //URL url1 = new URL("file:///c:/cred.ws");
            // System.out.println(url);
            URL url1 = new URL("file:///D:/Neil/X509up_u_ndb23");
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
            
            // String endpoint =   "http://tiber:8080/acmbadc/services/ACServer"; NDB
            String endpoint =   "http://escvig5.dl.ac.uk:8080/acmnerc/services/ACServer";
            Service  service = new Service();
            Call     call    = (Call) service.createCall();
            
            String tokenFileName = "C:/bodc.cred";
            SAXBuilder saxb = new SAXBuilder();
            org.jdom.Document authTokenDoc = saxb.build("file:///"+ tokenFileName );
            org.w3c.dom.Document domDoc = Converter.JDOMtoDOM( authTokenDoc );
            org.w3c.dom.Element foreignToken = domDoc.getDocumentElement();
            
            call.setTargetEndpointAddress( new java.net.URL(endpoint) );
            call.setOperationName( "getAuthorisationTokenInDOMElement" );
            call.addParameter( "cert", XMLType.XSD_STRING, ParameterMode.IN );
            call.addParameter( "cert2", XMLType.SOAP_ELEMENT, ParameterMode.IN );
            call.setReturnType(XMLType.SOAP_ELEMENT);
            
            
            Object[] ob = new Object[]{ cert3, foreignToken };
    //        Object[] ob = new Object[]{ cert3 };
            org.w3c.dom.Element ret = null;
            
            ret = (org.w3c.dom.Element) call.invoke(ob );
            org.jdom.input.DOMBuilder buildert = new org.jdom.input.DOMBuilder();
            org.jdom.Element el = buildert.build(ret);
            Document d = new Document(el);
            Saver.save(d,new File("c:/badc.cred"));
            /*
            FileWriter e = new FileWriter("c:/ws.cred");
            e.write(ret.toString());
            e.close();
            System.out.println(ret);
             */
        }
        catch(Exception e){
            System.out.println(e);
        }
    }
    
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        new TestWSServer(args);
    }
    
}
