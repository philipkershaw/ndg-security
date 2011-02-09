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
import org.jdom.output.*;
import ac.dl.xml.*;
import org.globus.util.Base64;
/**
 *
 *
 * @author  gjd37
 */
public class TestACClient {

    /** Creates a new instance of ACServertTest */
    public TestACClient(String[] args) {

        try {
            org.w3c.dom.Document doc = XML_DOMBuilder.parse(new File("c:/ws.cred"));
            org.w3c.dom.Element element  = doc.getDocumentElement();

            TokenReader reader = new TokenReader();

            uk.ac.cclrc.authorisation.AttributeList list =  reader.getAttributes(element);


            //System.out.println("Data access "+list.getDataAccessGroup());
            System.out.println("Data access "+list.getRoleSet());
            // System.out.println("Wrapper access "+list.getWrapperGroup()); NDB
            // System.out.println("Facility access "+list.getDPView()); NDB

            //getUserPrivilegesFromDB();
        } catch (Exception e){
            System.out.println(e);
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {



        new TestACClient(args);
    }

}