/*
 * AttributeList.java
 *
 * Created on July 16, 2003, 6:31 PM
 */

package uk.ac.cclrc.authorisation;

//import org.jdom.input.*;
//import org.jdom.output.*;
//import java.io.*;
//import java.util.*;
//import java.sql.*;
import org.jdom.*;
import ac.dl.xml.*;
import org.apache.log4j.*;
import java.util.*;

/**
 *
 * @author  asm67
 *
 *This class reads XML String and converts to Attribute Certificate or can be used
 * to add data to generate Attribute Certificate
 */
public class AttributeList {
    
    static Logger log = Logger.getLogger(AttributeList.class);
    
    public AttributeList(String version, String userDn, String issuerDn, String issuerName, String issuerSerialNumber,
        int[] notBefore, int[] notAfter, HashSet roleHashSet, String origin)
    {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        this.version = version;
        this.holder = userDn;
        this.issuer=issuerDn;
        this.issuerName = issuerName;
        this.issuerSerialNumber = issuerSerialNumber;
        
        this.validityNotAfter=notAfter;
        this.validityNotBefore=notBefore;
        this.roleSet = roleHashSet;

        this.provenance = origin;
    }
    
    public AttributeList(org.jdom.Element acInfo) throws Exception
    {
        PropertyConfigurator.configure(Config.getContextPath()+"logger.properties");
        parseAttributeList(acInfo);
    }
    
    //NOT CURRENTLY USED
    /*
    public String getAcInfoAsXMLString() throws Exception
    {
        try {
            Document doc = this.getJDOMDocument();
            // Convert to XML String and Return
            XMLOutputter outputter = new XMLOutputter();
            return outputter.outputString(doc);
    
        } catch (Exception e) {
            log.error("Unable to create Attribute List as XML String",e);
            throw e;
        }
    
    }
     */
    
    // NOT CURRENTLY USED
    /** This method is used to generate the ACInfo section of the authorisationToken
     *@param org.w3c.dom.Element  The resultSet Holding the one instance of the user
     *@exception    java.sql.SQLException
     */
    /*
    public org.w3c.dom.Element getAcInfoAsW3CElement() throws Exception
    {        
        // Convert to XML String and Return
        try {
            Document doc = this.getJDOMDocument();
            org.w3c.dom.Document w3cDoc = Converter.JDOMtoDOM(doc);
            org.w3c.dom.Element el = w3cDoc.getDocumentElement();
            return el;
            
        } catch (Exception e) {
            log.error("Unable to create Attribute Certificate as Element",e);
            throw e;
        }
    }
     */
    
    /** This method generates an empty namespace-aware DOM Document
     *@exception java.lang.Exception
     *@return org.w3c.dom.Document an empty DOM Document
     */
    public org.w3c.dom.Document getDOMDocument() throws Exception
    {
        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();

        //XML Signature needs to be namespace aware
        dbf.setNamespaceAware(true);

        javax.xml.parsers.DocumentBuilder db = null;
        org.w3c.dom.Document w3cDoc = null;
        
        db = dbf.newDocumentBuilder();
        w3cDoc = db.newDocument();
        Document jdomDoc = Converter.DOMtoJDOM( w3cDoc );
        jdomDoc = populateJDOMDoc( jdomDoc );
        w3cDoc = Converter.JDOMtoDOM( jdomDoc );
        
        return w3cDoc;
    }
    
    /** This method creates an empty Attribute Certificate as a JDOM Document
     *@param org.jdom.Document doc empty JDOM Document to which attribute certificate elements are added
     *@return org.jdom.Document empty Attribute Certificate
     */
    private Document populateJDOMDoc( Document doc )
    {
        Element attCert = new Element("attributeCertificate");
        Element acInfo = new Element("acInfo");

        //Build XML file
        doc.setRootElement(attCert);
        //set version
        Element versionElement = new Element("version");
        versionElement.setText(version);
        //set holder
        Element holderElement = new Element("holder");
        holderElement.setText(holder);
        //set issuer
        Element issuerElement = new Element("issuer");
        issuerElement.setText(issuer);
        //set issuer
        Element issuerNameElement = new Element("issuerName");
        issuerNameElement.setText(issuerName);
        //setissuerSerialNumber
        Element issuerSerialNumberElement = new Element("issuerSerialNumber");
        issuerSerialNumberElement.setText(issuerSerialNumber);
        //set validity
        Element validityElement = new Element("validity");
        //set validity not before
        Element validityNotBeforeElement = new Element("notBefore");
        //turn array into string
        StringBuffer notBefore = new StringBuffer();
        for(int i = 0;i<validityNotBefore.length;i++){
            if(i == (validityNotBefore.length -1)) notBefore.append(validityNotBefore[i]);
            else notBefore.append(validityNotBefore[i]+" ");
        }

        validityNotBeforeElement.setText(notBefore.toString());
        //set validity not after
        Element validityNotAfterElement = new Element("notAfter");
        StringBuffer notAfter = new StringBuffer();
        for(int i = 0;i<validityNotAfter.length;i++){
            if(i == (validityNotAfter.length -1)) notAfter.append(validityNotAfter[i]);
            else notAfter.append(validityNotAfter[i]+" ");
        }

        validityNotAfterElement.setText(notAfter.toString());
        //set Attributes
        Element attributesElement = new Element("attributes");

        Element roleSetElement = new Element("roleSet");

        Iterator roleSetIt = roleSet.iterator();
        while( roleSetIt.hasNext() )
        {
            String role = (String) roleSetIt.next();
            Element roleElement = new Element( "role" );
            Element roleName = new Element( "name" );
            roleSetElement.addContent( roleElement );
            roleElement.addContent( roleName );
            roleName.setText( role );
        }

        //set issuer
        Element provenanceElement = new Element("provenance");
        provenanceElement.setText(provenance);

        //Create XML tree
        attCert.addContent(acInfo);
        acInfo.addContent(versionElement);
        acInfo.addContent(holderElement);
        acInfo.addContent(issuerElement);
        acInfo.addContent(issuerNameElement);
        acInfo.addContent(issuerSerialNumberElement);
        validityElement.addContent(validityNotBeforeElement);
        validityElement.addContent(validityNotAfterElement);
        acInfo.addContent(validityElement);
        attributesElement.addContent( roleSetElement );
        acInfo.addContent(attributesElement);
        acInfo.addContent(provenanceElement);

        return doc;
    }
    
    // NOT CURRENTLY USED
    public Document getJDOMDocument() {

        Document doc = new Document();
        populateJDOMDoc( doc );
        return doc;
    }
    
    /** Used to check the time-validity of an attribute certificate
     *@return boolean whether the attribute certificate is still valid or not
     */
    public boolean isValid()  {
        
        GregorianCalendar notBeforeCal = new GregorianCalendar(validityNotBefore[0],validityNotBefore[1],validityNotBefore[2],validityNotBefore[3],validityNotBefore[4],validityNotBefore[5]);
        GregorianCalendar notAfterCal = new GregorianCalendar(validityNotAfter[0],validityNotAfter[1],validityNotAfter[2],validityNotAfter[3],validityNotAfter[4],validityNotAfter[5]);
        GregorianCalendar now = new GregorianCalendar();

        if(now.before(notBeforeCal)) return false;
        if(now.after(notAfterCal)) return false;
        return true;
    }
    public void setVersion(String version){
        this.version = version;
    }
    public String getVersion(){
        return this.version;
    }
    public void setHolder(String holder){
        this.holder = holder;
    }
    public String getHolder(){
        return this.holder;
    }
    public void setIssuer(String issuer){
        this.issuer = issuer;
    }
    public String getIssuer(){
        return issuer;
    }
    public void setIssuerName(String issuerName){
        this.issuerName=issuerName;
    }
    public String getIssuerName(){
        return this.issuerName;
    }
    public void setIssuerSerialNumber(String serialNumber){
        this.issuerSerialNumber=serialNumber;
    }
    public String getIssuerSerialNumber(){
        return this.issuerSerialNumber;
    }
    public void setValidityNotBefore(int[] notBefore){
        this.validityNotBefore=notBefore;
    }
    public int[] getValidityNotBefore(){
        return this.validityNotBefore;
    }
    public void setValidityNotAfter(int[] notAfter){
        this.validityNotAfter=notAfter;
    }
    public int[] getValidityNotAfter(){
        return this.validityNotAfter;
    }
    public HashSet getRoleSet(){
        return roleSet;
    }
    public void setProvenance(String origin){
        this.provenance=origin;
    }
    public String getProvenance(){
        return provenance;
    }
   
    /** Used to set the fields of the AttributeList object when an unsigned attribute certificate is passed in.
     *@param org.jdom.Element acInfo the attribute certificate 
     *@exception java.lang.Exception
     */
    private void parseAttributeList(Element acInfo) throws Exception
    {
        List elementList = acInfo.getChildren();
        Iterator iterator = elementList.iterator();
        String elementName;
        roleSet = new HashSet();

        while (iterator.hasNext()) {
            Element next = (Element) iterator.next();
            elementName=next.getName();

            if(elementName.equals("version")){

                this.version = next.getText().trim();
            }
            if(elementName.equals("holder")){

                this.holder = next.getText().trim();
            }
            if(elementName.equals("issuer")){ this.issuer = next.getText().trim(); }
            if(elementName.equals("issuerName")){this.issuerName = next.getText().trim() ;}
            if(elementName.equals("issuerSerialNumber")){ this.issuerSerialNumber = next.getText().trim();}
            if(elementName.equals("validity")){

                List validityList = next.getChildren();
                Iterator validityIterator = validityList.iterator();
                while (validityIterator.hasNext()) {

                    Element validityNext = (Element) validityIterator.next();
                    String validityElementName = validityNext.getName();

                    if(validityElementName.equals("notBefore")){
                        String notB = validityNext.getText().trim();
                        String[] notBS = notB.split(" ");
                        int[] notBI = new int[notBS.length];
                        for(int i= 0; i<notBS.length;i++){
                            notBI[i] = Integer.parseInt(notBS[i]);

                        }
                        this.validityNotBefore = notBI;
                    }
                    if(validityElementName.equals("notAfter")){
                        String notA = validityNext.getText().trim();
                        String[] notAS = notA.split(" ");
                        int[] notAI = new int[notAS.length];
                        for(int i= 0; i<notAS.length;i++){
                            notAI[i] = Integer.parseInt(notAS[i]);

                        }
                        this.validityNotAfter = notAI;
                    }
                }
            }

            if(elementName.equals("attributes")){

                List attributeList = next.getChildren();
                Iterator attributeIterator = attributeList.iterator();
                while (attributeIterator.hasNext()) {

                    Element attribNext = (Element) attributeIterator.next();
                    String attribElementName = attribNext.getName();
                    if(attribElementName.equals("roleSet"))
                    {
                        List roleSetList = attribNext.getChildren();
                        Iterator roleSetIterator = roleSetList.iterator();
                        while( roleSetIterator.hasNext() )
                        {
                            Element roleSetNext = (Element) roleSetIterator.next();
                            String roleSetElementName = roleSetNext.getName();

                            if( roleSetElementName.equals( "role" ) )
                            {
                                List roleList = roleSetNext.getChildren();
                                Iterator roleIterator = roleList.iterator();
                                while( roleIterator.hasNext() )
                                {
                                    Element roleNext = (Element) roleIterator.next();
                                    String roleElementName = roleNext.getName();

                                    if( roleElementName.equals( "name" ) )
                                    {
                                        String role = roleNext.getText().trim();
                                        roleSet.add( role );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if(elementName.equals("provenance")){this.provenance = next.getText().trim() ;}
        }
            
    }
    
    private String version;
    private String holder;
    private String issuer;
    private String issuerName;
    private String issuerSerialNumber;
    private int[] validityNotBefore;
    private int[] validityNotAfter;
    private HashSet roleSet;
    private String provenance;
}
