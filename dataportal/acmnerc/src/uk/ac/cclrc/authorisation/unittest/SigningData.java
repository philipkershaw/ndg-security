/*
 * SigningData.java
 *
 * Created on 12 November 2003, 14:33
 */

package uk.ac.cclrc.authorisation.unittest;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.interfaces.*;
import java.security.cert.*;
import org.globus.gsi.CertUtil;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import uk.ac.cclrc.authorisation.*;

import org.jdom.*;
import org.jdom.input.*;
import org.jdom.output.*;
import java.util.*;
import java.io.*;
import org.globus.util.Base64;
/**
 *
 * @author  gjd37
 */
public class SigningData {
    
    /** Creates a new instance of SigningData */
    public SigningData(String[] args) throws Exception {
        String message1 = "e";
        String message2 = "e";
        String sign = "d";
        
        String keyStoreFileName = System.getProperty("user.home")+File.separator+".keystore";
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keyStoreFileName), args[0].toCharArray());
        Key key = keystore.getKey("Dataportal", args[1].toCharArray());
        RSAPrivateKey prvKey = (RSAPrivateKey)key;
        java.security.cert.Certificate cert = keystore.getCertificate("Dataportal");
        
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(prvKey);
        signer.update(message1.getBytes());
        byte[] signatureBytes = signer.sign();
        //FileOutputStream w = new FileOutputStream("c:/sign");
        //w.write(signatureBytes);
        //w.close();
        byte[] encode = org.globus.util.Base64.encode(signatureBytes);
        
        FileOutputStream w = new FileOutputStream("c:/sign");
        ///w.write(encode);
        for(int i= 0;i < encode.length;i++){
            
        }
        w.write(encode);
        w.close();
        System.out.println("SIGNED DATA is "+signatureBytes);
        // byte[] bsign = signatureBytes;
        //System.out.println(sign);
        System.out.println("");
        System.out.println("");
        //System.out.println("Verifying signed by dataportal");
        
        // RSAPublicKey pubKey = (RSAPublicKey)cert.getPublicKey();
        //get certificate
        InputStream inStream = new FileInputStream("c:/dataportal.jks");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert1 = (X509Certificate)cf.generateCertificate(inStream);
        inStream.close();
        RSAPublicKey pubKey = (RSAPublicKey)cert1.getPublicKey();
        
        
        Signature verifier= Signature.getInstance("SHA1withRSA");
        verifier.initVerify(pubKey);
        //verifier.update("[B@1b16e521".getBytes());
        
        verifier.update(message1.getBytes());
        File e = new File("c:/sign");
        byte[] signfile= new byte[(int)e.length()];
        FileInputStream f = new FileInputStream(e);
        f.read(signfile);
        f.close();
       BufferedReader d1= new BufferedReader(new InputStreamReader(new ByteArrayInputStream(encode)));
        String certstring = d1.readLine();
        
        System.out.println("sting from encode is "+certstring);
        BufferedReader d= new BufferedReader(new FileReader("c:/sign"));
        String a= d.readLine();
        
        byte[] decode = org.globus.util.Base64.decode(a.getBytes());
        if(verifier.verify(decode)) System.out.println("Verified");
        else System.out.println("no");
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception{
        new SigningData(args);
        // tryGlobus();
        // reader();
        
    }
    
    public static void tryGlobus() throws Exception {
        X509Certificate hostCertificate;
        PrivateKey hostPrivateKey;
        PublicKey hostPublicKey;
        String messageText= "e";
        String signatureText = "e";
        String certFile = System.getProperty("user.home")+File.separator+".globus"+File.separator+"portalcert.pem";
        String keyFile = System.getProperty("user.home")+File.separator+".globus"+File.separator+"portalkey.pem";
        
        OpenSSLKey key = new BouncyCastleOpenSSLKey(keyFile.trim());
        
        hostPrivateKey = key.getPrivateKey();
        RSAPrivateKey prvKey = (RSAPrivateKey)hostPrivateKey;
        hostCertificate = CertUtil.loadCertificate(certFile.trim());
        hostPublicKey = hostCertificate.getPublicKey();
        RSAPublicKey pukey = (RSAPublicKey)hostPublicKey;
        
        
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(hostPrivateKey);
        signer.update(messageText.getBytes());
        byte[] signatureBytes = signer.sign();
        System.out.println("signed data");
        
        System.out.println("verifing data ......");
        /*Signature sigVerifier = Signature.getInstance("SHA1withRSA");
        sigVerifier.initVerify(pukey);
        sigVerifier.update(messageText.getBytes());
        if(sigVerifier.verify(signatureText.getBytes())) System.out.println("verified");
        else System.out.println("no");*/
        InputStream inStream = new FileInputStream("c:/dataportal.jks");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert1 = (X509Certificate)cf.generateCertificate(inStream);
        inStream.close();
        RSAPublicKey pubKey = (RSAPublicKey)cert1.getPublicKey();
        
        Signature verifier= Signature.getInstance("SHA1withRSA");
        verifier.initVerify(pubKey);
        //verifier.update("[B@1b16e521".getBytes());
        
        verifier.update(messageText.getBytes());
        if(verifier.verify(signatureBytes)) System.out.println("Verified");
        else System.out.println("no");
    }
    
    
    public static void reader() throws Exception {
        
        BufferedReader d= new BufferedReader(new FileReader("c:/sign"));
        String a= d.readLine();
        System.out.println(a);
         
        
    }
}
