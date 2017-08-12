package mpc;

import javacard.framework.ISOException;

/**
 *
 * @author Petr Svenda
 */
public class ECPointBuilder {
    public static final byte ECPOINT_INSTANCE_TYPE_SW = (byte) 1;
    public static final byte ECPOINT_INSTANCE_TYPE_NXP = (byte) 2;

    public static final byte TYPE_EC_FP_POINT = (byte) 100;

    public static final byte ECPOINT_LIB = ECPOINT_INSTANCE_TYPE_SW; // Set proper library based on the underlying provider
    public static final byte ECPOINT_TYPE = TYPE_EC_FP_POINT; 
    
    static ECCurve theCurve;
    static ECConfig ecc;
    
    static ECPointBase createPoint(short keyLen) {
        switch (ECPOINT_LIB) {
            case ECPOINT_INSTANCE_TYPE_SW: 
                return ECPoint_SW.createPoint(ecc);
            case ECPOINT_INSTANCE_TYPE_NXP: 
                ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
                break;
            default: 
                ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        }
        return null;
    }
    
    public static void allocate(ECCurve curve, ECConfig ecCfg) {
        theCurve = curve;
        ecc = ecCfg;
        
        switch (ECPOINT_LIB) {
            case ECPOINT_INSTANCE_TYPE_SW:
                ECPoint_SW.allocate(ecc, theCurve);
                break;
            case ECPOINT_INSTANCE_TYPE_NXP:
                ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
                break;
            default:
                ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        }
    }    
}
