/*
 * DNChecker.java
 *
 * Created on 25 August 2004, 15:32
 */

package uk.ac.cclrc.authorisation.util;


/**
 *
 * @author  ndb23
 */
public class DNFormatter {
    
    private String testDN, Cvalue, Ovalue, OUvalue, Lvalue, CNvalue, formattedDN;
    private char delimiter;
   
    
    /** Creates a new instance of DNChecker */
    public DNFormatter( String dn )
    {
        testDN = dn;
        int delimIndex = testDN.indexOf( "O=" ) - 1;
        delimiter = testDN.charAt( delimIndex );
  
    }
    
    public String formatDN()
    {
        Cvalue = getDNFieldValue( "C" );    
        Ovalue = getDNFieldValue( "O" );
        OUvalue = getDNFieldValue( "OU" );
        Lvalue = getDNFieldValue( "L" );
        CNvalue = getDNFieldValue( "CN" );
        
        formattedDN = "CN = " + CNvalue + "," + "L = " + Lvalue + "," + "OU = " + OUvalue + "," + 
            "O = " + Ovalue + "," + "C = " + Cvalue;
        return formattedDN;
    }
    
    public String getDNFieldValue( String fieldName )
    {
        String dnFieldValue = "";
        String fieldNameStr = fieldName + "=";
        int fieldNameLength = fieldNameStr.length();
        int fieldValueIndex = testDN.indexOf( fieldNameStr ) + fieldNameLength;
        int nextDelimIndex = testDN.indexOf( delimiter, fieldValueIndex );
        if( nextDelimIndex == -1 )
        {
            dnFieldValue = testDN.substring( fieldValueIndex, testDN.length() );
        }
        else
        {
            dnFieldValue = testDN.substring( fieldValueIndex, nextDelimIndex );
        }
        
        return dnFieldValue;
    }
    
    
    public static void main( String[] args )
    {
        DNFormatter tester = new DNFormatter( "/C=UK/O=eScience/OU=CLRC/L=DL/CN=neil bennett" );
        System.out.println( tester.getDNFieldValue("CN") );
    }
    
}
