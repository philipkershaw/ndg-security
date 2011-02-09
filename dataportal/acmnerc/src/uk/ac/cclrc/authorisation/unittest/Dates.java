/*
 * Dates.java
 *
 * Created on 13 November 2003, 09:50
 */

package uk.ac.cclrc.authorisation.unittest;
import java.util.*;
import org.apache.log4j.*;
/**
 *
 * @author  gjd37
 */
public class Dates {
    
    Logger log = Logger.getLogger(this.getClass().getName());
    
    /** Creates a new instance of Dates */
    public Dates(String[] args) {
        
        //GregorianCalendar calendar = new GregorianCalendar();
        log.info("hello");
        log.warn("dsfdsfgds");
       /* System.out.println("ERA: " + calendar.get(Calendar.ERA));
        System.out.println("YEAR: " + calendar.get(Calendar.YEAR));
        System.out.println("MONTH: " + calendar.get(Calendar.MONTH));
        System.out.println("WEEK_OF_YEAR: " + calendar.get(Calendar.WEEK_OF_YEAR));
        System.out.println("WEEK_OF_MONTH: " + calendar.get(Calendar.WEEK_OF_MONTH));
        System.out.println("DATE: " + calendar.get(Calendar.DATE));
        System.out.println("DAY_OF_MONTH: " + calendar.get(Calendar.DAY_OF_MONTH));
        System.out.println("DAY_OF_YEAR: " + calendar.get(Calendar.DAY_OF_YEAR));
        System.out.println("DAY_OF_WEEK: " + calendar.get(Calendar.DAY_OF_WEEK));
        System.out.println("DAY_OF_WEEK_IN_MONTH: "
        + calendar.get(Calendar.DAY_OF_WEEK_IN_MONTH));
        System.out.println("HOUR_OF_DAY: " + calendar.get(Calendar.HOUR_OF_DAY));
        System.out.println("MINUTE: " + calendar.get(Calendar.MINUTE));
        System.out.println("SECOND: " + calendar.get(Calendar.SECOND));
        calendar.clear(Calendar.HOUR_OF_DAY); // so doesn't override
        calendar.set(Calendar.HOUR, 11);
        System.out.println("HOUR: " + calendar.get(Calendar.HOUR));
       .equals("")) System.out.println("HOUR_OF_DAY: " + calendar.get(Calendar.HOUR_OF_DAY));
        System.out.println("MINUTE: " + calendar.get(Calendar.MINUTE));
        System.out.println(calendar.getGregorianChange().toString());*/
       /* System.out.println("BEFORES DATE");
        System.out.println("YEAR: " + calendar.get(Calendar.YEAR));
        System.out.println("MONTH: " + calendar.get(Calendar.MONTH));
        
        System.out.println("DATE: " + calendar.get(Calendar.DATE));
        
        System.out.println("HOUR_OF_DAY: " + calendar.get(Calendar.HOUR_OF_DAY));
        System.out.println("MINUTE: " + calendar.get(Calendar.MINUTE));
        System.out.println("SECOND: " + calendar.get(Calendar.SECOND));
        //calendar.clear(Calendar.HOUR_OF_DAY); // so doesn't override
        //calendar.set(Calendar.HOUR, 0);
        System.out.println("set hour as +2");
        int[] time = new int[6];
        time[0]= calendar.get(Calendar.YEAR);
        time[1]= calendar.get(Calendar.MONTH);
        time[2]= calendar.get(Calendar.DATE);
        time[3]= calendar.get(Calendar.HOUR_OF_DAY);
        time[4]= calendar.get(Calendar.MINUTE);
        time[5]= calendar.get(Calendar.SECOND);
        
        GregorianCalendar newCal = new GregorianCalendar(time[0],time[1],time[2],time[3],time[4]+66,time[5]);
        System.out.println("YEAR: " + newCal.get(Calendar.YEAR));
        System.out.println("MONTH: " + newCal.get(Calendar.MONTH));
        
        System.out.println("DATE: " + newCal.get(Calendar.DATE));
        
        System.out.println("HOUR_OF_DAY: " + newCal.get(Calendar.HOUR_OF_DAY));
        System.out.println("MINUTE: " + newCal.get(Calendar.MINUTE));
        System.out.println("SECOND: " + newCal.get(Calendar.SECOND));
        System.out.println("is first before second?");
        System.out.println(calendar.before(newCal));
        */
        //    System.out.println(time);
        go();
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        /*try{
            PropertyConfigurator.configure("c:/logger.propertiefs");
        }
        catch(Throwable e){
            System.out.println("safdfs"+e);
           PropertyConfigurator.configure("c:/logger.properties");
         
        }
         */
        BasicConfigurator.configure();
        
        System.out.println("456456456");
        new Dates(args);
    }
    
    public void go(){
        log.info("go go");
    }
    
}
