/*
 * StringFormatter.java
 *
 * Created on 25 August 2004, 15:32
 */

package uk.ac.cclrc.authorisation.util;

/**
 *
 * @author  ndb23
 */
public class StringFormatter {
    
    private String firstString;   // string to be formatted
    private int stringLength;     // length of string to be formatted
    
    private String Cvalue, Ovalue, OUvalue, Lvalue, CNvalue; // values of the different components of the DN
    private String formattedString; // complete formatted string
    private String dnDelim; // string that delimits components of the new DN
    private String dnStart; // string signifying which is the first element of the new DN
    private String dnEquals; // string signifying how equality is represented in each component of the DN


    public StringFormatter(String initString)
    {
        firstString = initString;
        stringLength = firstString.length();
    }

    /** This method specifies the next string to be formatted.
     *@param String newString The new string
     */        
    public void setNewString( String newString )
    {
        firstString = newString;
        stringLength = firstString.length();
    }

    /** Used to set the config for formatting DNs
     *@param String start The element of the DN that will start the formatted DN (this can only ever be CN or C)
     *@param String equality The string used to represent equality in the formatted DN
     *@param String delim The string used to delimit elements in the formatted DN
     */        
    public void setDNConfig( String start, String equality, String delim )
    {
        dnDelim = delim;
        dnStart = start;
        dnEquals = equality;
    }
  
    // formats DN strings
    /** Used to obtain a formatted DN once the configuration and new string have been set
     *@return String the formatted DN
     */            
    public String formatDN()
    {
        Cvalue = getDNFieldValue( "C" );    
        Ovalue = getDNFieldValue( "O" );
        OUvalue = getDNFieldValue( "OU" );
        Lvalue = getDNFieldValue( "L" );
        CNvalue = getDNFieldValue( "CN" );
        
        if( dnStart.equals( "CN" ) )
        {
            formattedString = "CN" + dnEquals + CNvalue + dnDelim + "L" + dnEquals + Lvalue + dnDelim +
                "OU" + dnEquals + OUvalue + dnDelim + "O" + dnEquals + Ovalue + dnDelim + "C" + dnEquals +
                Cvalue;
        }
        else
        {
            formattedString = "C" + dnEquals + Cvalue + dnDelim + "O" + dnEquals + Ovalue + dnDelim +
                "OU" + dnEquals + OUvalue + dnDelim + "L" + dnEquals + Lvalue + dnDelim + "CN" + dnEquals +
                CNvalue;
        }
        
        return formattedString;
    }
    
    /** Extracts the value of the specified element within the DN
     *@param String fieldName The name of the element whose value is required
     *@return String The value of the DN element
     */            
    public String getDNFieldValue( String fieldName )
    {
        
        String dnFieldValue = "";
        String fieldNameStr = fieldName + "=";
        
        int fieldNameLength = fieldNameStr.length();
        
        // the index at which the field value starts
        int fieldValueIndex = firstString.indexOf( fieldNameStr ) + fieldNameLength;
        
        // the index of the first delimiter after the current field value
        int nextDelimIndex = firstString.indexOf( "/", fieldValueIndex );
        
        if( nextDelimIndex == -1 ) // when the current field is the last field of the DN
        {
            dnFieldValue = firstString.substring( fieldValueIndex, firstString.length() );
        }
        else // when the current field is not the last field
        {
            dnFieldValue = firstString.substring( fieldValueIndex, nextDelimIndex );
        }
        
        return dnFieldValue;
    }

    /** Removes quotes from a quoted string
     *@exception Exception
     *@return String The unquoted string
     */            
    public String removeQuotes() throws Exception
    {
        if( firstString.charAt( 0 ) != '"' || firstString.charAt( stringLength - 1 ) != '"' )
        {
            throw new Exception( "SQL query strings in the config file must be start and end with quotation marks" );
        }
        String unquotedString = firstString.substring(1,stringLength-1);                
        return unquotedString;
    }

    /** Adds quotes to each element of a list of unquoted strings
     *@return String The quoted list
     */            
    public String addQuotesToList()
    {
        
        String[] unquotedArray = firstString.split( ", " ); // obtains an array from the unquoted list
        int numOfElements = unquotedArray.length;
        StringBuffer quotedList = new StringBuffer();
        quotedList.append( "'" + unquotedArray[ 0 ] + "'" );
        for( int i = 1; i < numOfElements; i++ )
        {
            quotedList.append( ",'" + unquotedArray[ i ] + "'" );
        }
        String quotedString = quotedList.toString();
        return quotedString;
    }
    
    public static void main( String[] args )
    {
        StringFormatter tester = new StringFormatter( "/C=UK/O=eScience/OU=CLRC/L=DL/CN=neil bennett" );
        System.out.println( tester.getDNFieldValue("CN") );
        System.out.println( tester.formatDN() );
    }
    
    
}
