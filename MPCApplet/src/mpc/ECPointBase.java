package mpc;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECPointBase implements javacard.security.ECKey {
    static KeyAgreement ECMultiplHelper = null;
    static KeyAgreement ECMultiplHelperDecrypt = null;

    static KeyPair disposable_pair = null;
    static ECPrivateKey disposable_priv = null;
    static KeyPair disposable_pairDecrypt = null;
    static ECPrivateKey disposable_privDecrypt = null;
    
    static ECCurve theCurve;
    
    static byte[] TempBuffer65 = null;
    static byte[] pt_A_arr = null;          // Check if can share with TempBuffer65
    static byte[] pointTpmArray = null;     // Check if can share with TempBuffer65
    
    
    static void allocate(ECCurve curve) {
        theCurve = curve;
        disposable_pair = theCurve.newKeyPair(disposable_pair);
        disposable_priv = (ECPrivateKey) disposable_pair.getPrivate();
        disposable_pair.genKeyPair();
        disposable_pairDecrypt = theCurve.newKeyPair(disposable_pairDecrypt);
        disposable_privDecrypt = (ECPrivateKey) disposable_pairDecrypt.getPrivate();
        disposable_pairDecrypt.genKeyPair();

        TempBuffer65 = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_CARRY_65, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        pointTpmArray = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_CARRY_65, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        pt_A_arr = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_CARRY_65, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
    }

    public void initializeECPoint_SecP256r1() {
        this.setFieldFP(SecP256r1.p, (short) 0, (short) SecP256r1.p.length);
        this.setA(SecP256r1.a, (short) 0, (short) SecP256r1.a.length);
        this.setB(SecP256r1.b, (short) 0, (short) SecP256r1.b.length);
        this.setG(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
        this.setR(SecP256r1.r, (short) 0, (short) SecP256r1.r.length);
    }

    public void setW(byte[] g, short gOffset, short gLen) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public short getW(byte[] g, short gOffset) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return -1;
    }    
    
    public short ScalarMultiplication(ECPointBase BasePoint, KeyAgreement ecKeyAgreement, byte[] result) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return -1;
    }
    public short ScalarMultiplication(byte[] BasePoint, short BasePointOffset, short BasePointLen, byte[] value, byte[] result) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return -1;
    }
    public void ScalarMultiplication(ECPointBase BasePoint, KeyAgreement ecKeyAgreement, ECPointBase ResultECPoint) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }
    public short ScalarMultiplication(byte[] BasePoint, short BasePointOffset, short BasePointLen, KeyAgreement ecKeyAgreement, byte[] result) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return -1;
    }
    public void ScalarMultiplication(ECPointBase BasePoint, byte[] value, ECPointBase ResultECPoint) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }
    
    
    
    
    public static void ECPointAddition(ECPointBase PointA, ECPointBase PointB, ECPointBase ResultECPoint) {
        PointB.getW(pointTpmArray, (short) 0);
        ECPointAddition(PointA, pointTpmArray, (short) 0, ResultECPoint);
    }

    public static void ECPointAddition(ECPointBase PointA, byte[] PointB, ECPointBase ResultECPoint) {
        ECPointAddition(PointA, PointB, (short) 0, ResultECPoint);
    }

    public static void ECPointAddition(ECPointBase PointA, byte[] PointB, short PointBOffset, ECPointBase ResultECPoint) {
        if (PointA != ResultECPoint) {
            PointA.getW(pt_A_arr, (short) 0);
            ResultECPoint.setW(pt_A_arr, (short) 0, (short) pt_A_arr.length);
        }
        ResultECPoint.AddPoint(PointB, PointBOffset, Consts.SHARE_SIZE_CARRY_65);
    }
    
    void AddPoint(byte[] data, short dataOffset, short dataLen) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    
    
    //
    // ECKey methods
    //
    public void setFieldFP(byte[] bytes, short s, short s1) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public void setFieldF2M(short s) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public void setFieldF2M(short s, short s1, short s2) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public void setA(byte[] bytes, short s, short s1) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public void setB(byte[] bytes, short s, short s1) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public void setG(byte[] bytes, short s, short s1) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public void setR(byte[] bytes, short s, short s1) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public void setK(short s) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public short getField(byte[] bytes, short s) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return (short) -1;
    }

    public short getA(byte[] bytes, short s) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return (short) -1;
    }

    public short getB(byte[] bytes, short s) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return (short) -1;
    }

    public short getG(byte[] bytes, short s) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return (short) -1;
    }

    public short getR(byte[] bytes, short s) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return (short) -1;
    }

    public short getK() throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return (short) -1;
    }
    
    
    /* unused 20170811    
    //static byte[] uncompressed_arr = null;
     //static byte[] y_uncompressed_arr = null;
     //static Bignat y_Bn = null;
     //static Bignat p_Bn = null;
     //static Bignat _y_Bn = null;
 
    //uncompressed_arr = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_CARRY_65, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
     y_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
     p_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
     _y_Bn = new Bignat(Consts.SHARE_SIZE_32, false);

    public static void ECPointNegation(ECPointBase Point, ECPointBase ResultECPoint) {
     Point.getW(uncompressed_arr, (short) 0);
     ECPointNegation(uncompressed_arr, (short) 0, ResultECPoint);
     }

     public static void ECPointNegation(byte[] Point, short PointOffset, ECPointBase ResultECPoint) {
     y_Bn.from_byte_array(Consts.SHARE_SIZE_32, (short) 0, Point, (short) (PointOffset + 33));

     p_Bn.from_byte_array((short) SecP256r1.p.length, (short) 0, SecP256r1.p, (short) 0);

     // ECPointNegation
     if (y_Bn.lesser(p_Bn) == true) { // y<p
     _y_Bn.copy(p_Bn);
     _y_Bn.times_minus(y_Bn, (short) 0, (short) 1);
     } else {// y>p
     _y_Bn.copy(y_Bn);
     _y_Bn.times_minus(p_Bn, (short) 0, (short) 1);
     }

     _y_Bn.to_byte_array(Consts.SHARE_SIZE_CARRY_65, (short) 0, Point, (short) (PointOffset + (short) (Consts.SHARE_SIZE_32 + 1)));

     ResultECPoint.setW(Point, PointOffset, Consts.SHARE_SIZE_CARRY_65);
     }
    
     /*  20170811 unused      
     public static ECPointWrapper ECPointSubtraction(ECPointWrapper PointA, ECPointWrapper PointB) {

     // inverse PointB
     ECPointWrapper InversePointB = ECCurve.createPoint(SecP256r1.KEY_LENGTH);
     EC_Utils.initializeECPoint(InversePointB);
     ECPointNegation(PointB, InversePointB);

     // Add the two points
     ECPointWrapper ResultECPoint = ECCurve.createPoint( SecP256r1.KEY_LENGTH);
     EC_Utils.initializeECPoint(ResultECPoint);

     ECPointAddition(PointA, InversePointB, ResultECPoint);

     return ResultECPoint;
     }
     */

    public void copyDomainParametersFrom(ECKey eckey) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }
    
}
