package mpc;

import javacard.framework.JCSystem;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class QuorumContext {
    // Keys
    public DKG KeyPair;

    // Signing
    public Bignat signature_counter = null;
    public byte[] secret_seed = null; // = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    public QuorumContext(ECConfig eccfg, ECCurve curve) {
        signature_counter = new Bignat(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        secret_seed = new byte[Consts.SECRET_SEED_SIZE];
        KeyPair = new DKG(curve);
    }
    public void Reset() {
        signature_counter.zero();
        KeyPair.Invalidate(true);
    }
}
