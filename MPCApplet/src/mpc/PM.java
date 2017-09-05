package mpc;

import javacard.framework.ISOException;

/**
 * Utility class for performance profiling. Contains definition of performance trap 
 * constants and trap reaction method. 
* @author Petr Svenda
 */
public class PM {
    public static short m_perfStop = -1; // Performace measurement stop indicator

    // Performance-related debugging response codes
    public static final short PERF_START        = (short) 0x0001;
            
    public static final short TRAP_UNDEFINED = (short) 0xffff;

    public static final short TRAP_CRYPTOPS_ENCRYPT = (short) 0x7580;
    public static final short TRAP_CRYPTOPS_ENCRYPT_1 = (short) (TRAP_CRYPTOPS_ENCRYPT + 1);
    public static final short TRAP_CRYPTOPS_ENCRYPT_2 = (short) (TRAP_CRYPTOPS_ENCRYPT + 2);
    public static final short TRAP_CRYPTOPS_ENCRYPT_3 = (short) (TRAP_CRYPTOPS_ENCRYPT + 3);
    public static final short TRAP_CRYPTOPS_ENCRYPT_4 = (short) (TRAP_CRYPTOPS_ENCRYPT + 4);
    public static final short TRAP_CRYPTOPS_ENCRYPT_5 = (short) (TRAP_CRYPTOPS_ENCRYPT + 5);
    public static final short TRAP_CRYPTOPS_ENCRYPT_6 = (short) (TRAP_CRYPTOPS_ENCRYPT + 6);
    public static final short TRAP_CRYPTOPS_ENCRYPT_COMPLETE = TRAP_CRYPTOPS_ENCRYPT_6;
    
    public static final short TRAP_CRYPTOPS_DECRYPTSHARE = (short) 0x7570;
    public static final short TRAP_CRYPTOPS_DECRYPTSHARE_1 = (short) (TRAP_CRYPTOPS_DECRYPTSHARE + 1);
    public static final short TRAP_CRYPTOPS_DECRYPTSHARE_2 = (short) (TRAP_CRYPTOPS_DECRYPTSHARE + 2);
    public static final short TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE = TRAP_CRYPTOPS_DECRYPTSHARE_2;
    
    public static final short TRAP_CRYPTOPS_SIGN = (short) 0x7560;
    public static final short TRAP_CRYPTOPS_SIGN_1 = (short) (TRAP_CRYPTOPS_SIGN + 1);
    public static final short TRAP_CRYPTOPS_SIGN_2 = (short) (TRAP_CRYPTOPS_SIGN + 2);
    public static final short TRAP_CRYPTOPS_SIGN_3 = (short) (TRAP_CRYPTOPS_SIGN + 3);
    public static final short TRAP_CRYPTOPS_SIGN_4 = (short) (TRAP_CRYPTOPS_SIGN + 4);
    public static final short TRAP_CRYPTOPS_SIGN_5 = (short) (TRAP_CRYPTOPS_SIGN + 5);
    public static final short TRAP_CRYPTOPS_SIGN_6 = (short) (TRAP_CRYPTOPS_SIGN + 6);
    public static final short TRAP_CRYPTOPS_SIGN_7 = (short) (TRAP_CRYPTOPS_SIGN + 7);
    public static final short TRAP_CRYPTOPS_SIGN_8 = (short) (TRAP_CRYPTOPS_SIGN + 8);
    public static final short TRAP_CRYPTOPS_SIGN_9 = (short) (TRAP_CRYPTOPS_SIGN + 9);
    public static final short TRAP_CRYPTOPS_SIGN_10 = (short) (TRAP_CRYPTOPS_SIGN + 10);
    public static final short TRAP_CRYPTOPS_SIGN_COMPLETE = TRAP_CRYPTOPS_SIGN_10;
    

    public static void check(short stopCondition) {
        if (PM.m_perfStop == stopCondition) {
            ISOException.throwIt(stopCondition);
        }
    }
}
