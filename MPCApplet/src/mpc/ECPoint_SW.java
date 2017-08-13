package mpc;

import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.KeyAgreement;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECPoint_SW extends mpc.ECPointBase {
    public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN = (byte) 3;
    public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY = (byte) 6;
    
    static ResourceManager rm;

    static ECPoint fnc_addPoint_other = null;
    static ECPoint fnc_ScalarMultiplication_basePoint = null;
    static ECPoint fnc_ScalarMultiplication_resultPoint = null;
    
    ECPoint         m_swECPoint;
    
    private ECPoint_SW(ECPoint point) {
        m_swECPoint = point;
    }
    
    static ECPoint_SW createPoint(ECConfig ecc) {
        return new mpc.ECPoint_SW(new ECPoint(theCurve, ecc.ech));
    }    
    
    public static void allocate(ECConfig ecc, ECCurve curve) {
        rm = ecc.rm;
        theCurve = curve;
        if (fnc_addPoint_other == null) {
            fnc_addPoint_other = new ECPoint(theCurve, ecc.ech);
            //rm.locker.registerLock(fnc_addPoint_other);
        }
        if (fnc_ScalarMultiplication_basePoint == null) {
            fnc_ScalarMultiplication_basePoint = new ECPoint(theCurve, ecc.ech);
            fnc_ScalarMultiplication_resultPoint = fnc_ScalarMultiplication_basePoint; // reuse same point - BUGBUG: use proper ResourceManager for sharing
            //rm.locker.registerLock(fnc_ScalarMultiplication_basePoint);
        }
        
/* unused        
        // TODO: JC 3.0.5 introduces KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY - but not yet supported on available cards
        ECMultiplHelper = KeyAgreement.getInstance(KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY, false);
        ECMultiplHelperDecrypt = KeyAgreement.getInstance(KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY, false);
*/        
    }
    
    public short ScalarMultiplication(byte[] BasePoint, short BasePointOffset, short BasePointLen, byte[] value, byte[] result) {
        //rm.locker.lock(fnc_ScalarMultiplication_basePoint);
        fnc_ScalarMultiplication_basePoint.getCurve().setG(BasePoint, BasePointOffset, BasePointLen);
        fnc_ScalarMultiplication_basePoint.updatePointObjects(); // After changing curve parameters, internal objects needs to be actualized
        
        fnc_ScalarMultiplication_basePoint.setW(BasePoint, BasePointOffset, BasePointLen);
        fnc_ScalarMultiplication_basePoint.multiplication(value, (short) 0, (short) value.length);

        short len = fnc_ScalarMultiplication_basePoint.getW(result, (short) 0);
        //rm.locker.unlock(fnc_ScalarMultiplication_basePoint);

        return len;
    }

    public short ScalarMultiplication(ECPointBase BasePoint, KeyAgreement ecKeyAgreement, byte[] result) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return -1;
    }
    
    public void ScalarMultiplication(ECPointBase BasePoint, KeyAgreement ecKeyAgreement, ECPointBase ResultECPoint) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public short ScalarMultiplication(byte[] BasePoint, short BasePointOffset, short BasePointLen, KeyAgreement ecKeyAgreement, byte[] result) {
        return -1;
    }
    
    public void ScalarMultiplication(ECPointBase BasePoint, byte[] value, ECPointBase ResultECPoint) {
        short len = BasePoint.getW(TempBuffer65, (short) 0);
        fnc_ScalarMultiplication_resultPoint.getCurve().setG(TempBuffer65, (short) 0, len);
        fnc_ScalarMultiplication_resultPoint.updatePointObjects(); // After changing curve parameters, internal objects needs to be actualized
        
        fnc_ScalarMultiplication_resultPoint.setW(TempBuffer65, (short) 0, len);
        fnc_ScalarMultiplication_resultPoint.multiplication(value, (short) 0, (short) value.length);
        len = fnc_ScalarMultiplication_resultPoint.getW(TempBuffer65, (short) 0);
        ResultECPoint.setW(TempBuffer65, (short) 0, len);
    }
    
    
    public void setW(byte[] g, short gOffset, short gLen) {
        m_swECPoint.setW(g, gOffset, gLen);
    }

    public short getW(byte[] g, short gOffset) {
        return m_swECPoint.getW(g, gOffset);
    }
    
    void AddPoint(byte[] data, short dataOffset, short dataLen) {
        //rm.locker.lock(fnc_addPoint_other);
        fnc_addPoint_other.setW(data, dataOffset, dataLen);        
        m_swECPoint.add(fnc_addPoint_other);
        //rm.locker.unlock(fnc_addPoint_other);
    }    

    //
    // ECKey methods
    //
    public void setFieldFP(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.thePoint.setFieldFP(bytes, s, s1); 
    }

    public void setFieldF2M(short s) throws CryptoException {
        m_swECPoint.thePoint.setFieldF2M(s);
    }

    public void setFieldF2M(short s, short s1, short s2) throws CryptoException {
        m_swECPoint.thePoint.setFieldF2M(s, s1, s2);
    }

    public void setA(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.thePoint.setA(bytes, s, s1);
    }

    public void setB(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.thePoint.setB(bytes, s, s1);
    }

    public void setG(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.thePoint.setG(bytes, s, s1);
    }

    public void setR(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.thePoint.setR(bytes, s, s1);
    }

    public void setK(short s) {
        m_swECPoint.thePoint.setK(s);
    }

    public short getField(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.thePoint.getField(bytes, s);
    }

    public short getA(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.thePoint.getA(bytes, s);
    }

    public short getB(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.thePoint.getB(bytes, s);
    }

    public short getG(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.thePoint.getG(bytes, s);
    }

    public short getR(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.thePoint.getR(bytes, s);
    }

    public short getK() throws CryptoException {
        return m_swECPoint.thePoint.getK();
    }
}
