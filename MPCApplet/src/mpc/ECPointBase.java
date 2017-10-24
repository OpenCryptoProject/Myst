package mpc;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import mpc.jcmathlib.*;
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

        TempBuffer65 = JCSystem.makeTransientByteArray(Consts.SHARE_DOUBLE_SIZE_CARRY, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        pointTpmArray = JCSystem.makeTransientByteArray(Consts.SHARE_DOUBLE_SIZE_CARRY, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        pt_A_arr = JCSystem.makeTransientByteArray(Consts.SHARE_DOUBLE_SIZE_CARRY, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
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
    public short ScalarMultiplication(ECPointBase BasePoint, byte[] value, byte[] result) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return -1;
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
        ResultECPoint.AddPoint(PointB, PointBOffset, Consts.SHARE_DOUBLE_SIZE_CARRY);
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
    
    public void copyDomainParametersFrom(ECKey eckey) throws CryptoException {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }
    
}
