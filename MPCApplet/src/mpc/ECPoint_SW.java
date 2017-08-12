package mpc;

import javacard.security.CryptoException;
import javacard.security.KeyAgreement;

/**
 *
 * @author Petr Svenda
 */
public class ECPoint_SW extends mpc.ECPointBase {
    public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN = (byte) 3;
    public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY = (byte) 6;
    
    static ECPointSW fnc_addPoint_other = null;
    
    ECPointSW    m_swECPoint;
    
    private ECPoint_SW(ECPointSW point) {
        m_swECPoint = point;
    }
    
    static ECPoint_SW createPoint(byte keyType, short keyLen) {
        if (keyType == ECPointBuilder.TYPE_EC_FP_POINT) {
            return new mpc.ECPoint_SW(new mpc.ECPointSW(keyLen));
        }
        return null;
    }    
    
    public static void allocate() {
        fnc_addPoint_other = null; // BUGBUG: reference to ECPoint

        // TODO: JC 3.0.5 introduces KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY - but not yet supported on available cards
        ECMultiplHelper = KeyAgreement.getInstance(KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY, false);
        ECMultiplHelperDecrypt = KeyAgreement.getInstance(KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY, false);
    }
    
    public void setW(byte[] g, short gOffset, short gLen) {
        m_swECPoint.setW(g, gOffset, gLen);
    }

    public short getW(byte[] g, short gOffset) {
        return m_swECPoint.getW(g, gOffset);
    }
    
    void AddPoint(byte[] data, short dataOffset, short dataLen) {
        fnc_addPoint_other.lock();
        fnc_addPoint_other.setW(data, dataOffset, dataLen);        
        m_swECPoint.add(fnc_addPoint_other);
        fnc_addPoint_other.unlock();
    }    

    //
    // ECKey methods
    //
    public void setFieldFP(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.setFieldFP(bytes, s, s1); 
    }

    public void setFieldF2M(short s) throws CryptoException {
        m_swECPoint.setFieldF2M(s);
    }

    public void setFieldF2M(short s, short s1, short s2) throws CryptoException {
        m_swECPoint.setFieldF2M(s, s1, s2);
    }

    public void setA(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.setA(bytes, s, s1);
    }

    public void setB(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.setB(bytes, s, s1);
    }

    public void setG(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.setG(bytes, s, s1);
    }

    public void setR(byte[] bytes, short s, short s1) throws CryptoException {
        m_swECPoint.setR(bytes, s, s1);
    }

    public void setK(short s) {
        m_swECPoint.setK(s);
    }

    public short getField(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.getField(bytes, s);
    }

    public short getA(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.getA(bytes, s);
    }

    public short getB(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.getB(bytes, s);
    }

    public short getG(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.getG(bytes, s);
    }

    public short getR(byte[] bytes, short s) throws CryptoException {
        return m_swECPoint.getR(bytes, s);
    }

    public short getK() throws CryptoException {
        return m_swECPoint.getK();
    }
}
