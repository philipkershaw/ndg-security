/*
 * InvalidauthorisationToken.java
 *
 * Created on 26 October 2003, 22:22
 */

package uk.ac.cclrc.authorisation.client;

/**
 *
 * @author  Administrator
 */
public class InvalidAuthorisationTokenException extends java.lang.Exception {
    
    /**
     * Creates a new instance of <code>InvalidauthorisationToken</code> without detail message.
     */
    public InvalidAuthorisationTokenException() {
    }
    
    
    /**
     * Constructs an instance of <code>InvalidauthorisationToken</code> with the specified detail message.
     * @param msg the detail message.
     */
    public InvalidAuthorisationTokenException(String msg) {
        super(msg);
    }
}
