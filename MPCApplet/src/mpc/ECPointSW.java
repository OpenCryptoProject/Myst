package mpc;

import javacard.framework.ISOException;
import javacard.security.CryptoException;

/**
 *
 * @author xsvenda
 */
public class ECPointSW {
    ECPointSW(short keyLen) {}
    
    void lock() {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }
    void unlock() {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }
    public void setW(byte[] g, short gOffset, short gLen) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
    }

    public short getW(byte[] g, short gOffset) {
        ISOException.throwIt(Consts.SW_NOTSUPPORTEDYET);
        return -1;
    }    
    
    public void add(ECPointSW other) {
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
}
