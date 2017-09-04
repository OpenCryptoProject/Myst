package mpc;

import javacard.framework.JCSystem;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class QuorumContext {
    // Keys
    public DKG KeyPair;

    public short NUM_PLAYERS = 0; 
    public short CARD_INDEX_THIS = 0; 

    public static boolean SETUP = false; // Have the scheme parameters been set?

    // Signing
    public Bignat signature_counter = null;
    public byte[] secret_seed = null; // = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    public QuorumContext(ECConfig eccfg, ECCurve curve) {
        signature_counter = new Bignat(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        secret_seed = new byte[Consts.SECRET_SEED_SIZE];
        KeyPair = new DKG(curve);
    }
    public void Reset() {
	NUM_PLAYERS = 0;
        CARD_INDEX_THIS = 0;     
        SETUP = false;
        signature_counter.zero();
        KeyPair.Invalidate(true);
    }
}
