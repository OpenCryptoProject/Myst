package mpc;

import javacard.framework.JCSystem;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class CryptoObjects {
    // Keys
    public static DKG KeyPair;

    // Signing
    public static Bignat signature_counter = null;
    public static byte[] secret_seed = null; // = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    public static Bignat Sign_counter = null;

    public static void allocate(ECConfig eccfg) {
        Sign_counter = new Bignat((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        signature_counter = new Bignat(Consts.SHARE_SIZE_32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        
        secret_seed = new byte[Consts.SHARE_SIZE_32];
    }
    public static void Reset() {
        signature_counter.zero();
        KeyPair.Invalidate(true);
    }
}
