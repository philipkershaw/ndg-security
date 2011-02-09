/*
 * KeyPopulation.java
 *
 * Created on 25 August 2004, 15:32
 */

package uk.ac.cclrc.authorisation.util;

import java.io.*;
import java.sql.*;
import org.apache.log4j.*;
import java.net.*;
import java.util.*;
import uk.ac.cclrc.authorisation.*;
import java.security.cert.*;
import java.security.*;
import java.security.InvalidKeyException;
import java.security.interfaces.*;


/**
 *
 * @author  ndb23
 */
public class KeyPopulation {
    
    //private String fileName;
    static Logger log = Logger.getLogger(KeyPopulation.class);
    
/*    
    public KeyPopulation(String name)
    {
        fileName = name;
    }
*/
    
    public void insert()
    {
        try
        {
            URL fileURL = new URL("file:///D:/dataportal/acmnerc/web/WEB-INF/nerc.cert");
            URLConnection con = fileURL.openConnection();
            
            InputStream is = con.getInputStream();
            
            
            byte[] byteArray = new byte[ 1400 ];
            int bytesRead = is.read( byteArray );
            System.out.println("bytes read = " + bytesRead);
            
            byte[] destArray = new byte[ bytesRead ];
            System.arraycopy(byteArray, 0, destArray, 0, bytesRead);
            byte[] encodedArray = org.globus.util.Base64.encode( destArray );
            String destArrayString = new String( encodedArray );
            
            Class.forName("com.mysql.jdbc.Driver");
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test_ceh");
            Statement stat = conn.createStatement();
            ResultSet rs = stat.executeQuery("UPDATE role_mappings SET ext_pub_key='"+destArrayString+"' WHERE ext_orgn='BODC'");
            
        }
        catch( Exception e )
        {
            e.printStackTrace();
        }
        
    }
    
    public static void main( String args[] )
    {
        KeyPopulation kp = new KeyPopulation();
        kp.insert();
        System.out.println("finished!");
    }
    
}
