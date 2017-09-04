package mpc;

/**
 *
 * @author Petr Svenda
 */
public class Consts {
    // Manually updated version of corresponding git commit
    public final static byte[] GIT_COMMIT_MANUAL = {(byte) 0x01, (byte) 0x14, (byte) 0x20, (byte) 0xaf};
            
    // MAIN INSTRUCTION CLASS
    public final static byte CLA_MPC				= (byte) 0xB0;

    // INStructions
    // Card Management

    public final static byte INS_QUORUM_SETUP_NEW		= (byte) 0x01;
    public final static byte INS_PERSONALIZE_CARDINFO           = (byte) 0x02;
    public final static byte INS_QUORUM_RESET                   = (byte) 0x03;
    public final static byte INS_TESTRSAMULT                    = (byte) 0x04;
    public final static byte INS_SET_BACKDOORED_EXAMPLE         = (byte) 0x05;
    public final static byte INS_TESTECC                        = (byte) 0x06;
    public final static byte INS_QUORUM_REMOVE                  = (byte) 0x07;
    public final static byte INS_PERSONALIZE_INITIALIZE         = (byte) 0x08;
    public final static byte INS_PERSONALIZE_SET_USER_AUTH_PUBKEY = (byte) 0x09;
    
    
    
    

    // KeyGen Operations
    public final static byte INS_KEYGEN_INIT			= (byte) 0x10;
    public final static byte INS_KEYGEN_RETRIEVE_COMMITMENT	= (byte) 0x11;
    public final static byte INS_KEYGEN_STORE_COMMITMENT	= (byte) 0x12;
    public final static byte INS_KEYGEN_STORE_PUBKEY		= (byte) 0x13;
    public final static byte INS_KEYGEN_RETRIEVE_PUBKEY         = (byte) 0x14;
    public final static byte BUGBUG_INS_KEYGEN_RETRIEVE_PRIVKEY	= (byte) 0x15;
    public final static byte INS_KEYGEN_RETRIEVE_AGG_PUBKEY     = (byte) 0x16;

    public final static byte INS_KEYPROPAGATION_RETRIEVE_PRIVKEY_SHARES = (byte) 0x20;
    public final static byte INS_KEYPROPAGATION_SET_PRIVKEY_SHARES      = (byte) 0x21;
    

    // Encryption/Decryption Operations
    public final static byte INS_ENCRYPT			= (byte) 0x50;
    public final static byte INS_DECRYPT			= (byte) 0x51;
    
    
    public final static byte INS_GENERATE_RANDOM                = (byte) 0x55;

    // Signing Operations
    // 0x60 to 0x6F and 0x90 to 0x9F are not allowed according to ISO 7816-3 and -4
    public final static byte INS_SIGN_INIT			= (byte) 0x70; 
    public final static byte INS_SIGN_RETRIEVE_HASH		= (byte) 0x71;
    public final static byte INS_SIGN_STORE_HASH		= (byte) 0x72;
    public final static byte INS_SIGN_STORE_RI			= (byte) 0x73;
    public final static byte INS_SIGN_STORE_RI_N_HASH		= (byte) 0x74;
    public final static byte INS_SIGN_RETRIEVE_RI		= (byte) 0x75;
    public final static byte INS_SIGN_RETRIEVE_RI_N_HASH	= (byte) 0x76;
    public final static byte BUGBUG_INS_SIGN_RETRIEVE_KI	= (byte) 0x77; // BUGBUG: only for testing, remove 
    public final static byte BUGBUG_INS_SIGN_RETRIEVE_R		= (byte) 0x78; // BUGBUG: only for testing, remove 
    public final static byte INS_SIGN                           = (byte) 0x79;
    public final static byte INS_SIGN_GET_CURRENT_COUNTER       = (byte) 0x7a;
    
            
    //Low level Operations
    public final static byte INS_ADDPOINTS						= (byte) 0x80;
    
    // Custom error response codes
    public static final short SW_SUCCESS                        = (short) 0x9000;
    public static final short SW_TOOMANYPLAYERS                 = (short) 0x7000;
    public static final short SW_INCORRECTSTATE                 = (short) 0x7001;
    public static final short SW_INVALIDHASH                    = (short) 0x7002;
    public static final short SW_INVALIDYSHARE                  = (short) 0x7003;
    public static final short SW_SHAREALREADYSTORED             = (short) 0x7004;
    public static final short SW_CANTALLOCATE_BIGNAT            = (short) 0x7005;
    public static final short SW_INVALIDPOINTTYPE               = (short) 0x7006;
    public static final short SW_NOTSUPPORTEDYET                = (short) 0x7007;
    public static final short SW_INTERNALSTATEMISMATCH          = (short) 0x7008;
    public static final short SW_INVALIDPLAYERINDEX             = (short) 0x7009;
    
    
    

    // Performance-related debugging response codes
    public static final short PERF_DECRYPT                      = (short) 0x7770;
    public static final short PERF_ENCRYPT                      = (short) 0x6660;
    public static final short PERF_SIGN                         = (short) 0x5550;
    
    // Global applet settings
    public static final short MAX_NUM_PLAYERS                     = (short) 15;   // Maximum number of allowed players

    // TLV types
    public final static byte TLV_TYPE_CARDUNIQUEDID    = (byte) 0x40;
    public final static byte TLV_TYPE_KEYPAIR_STATE    = (byte) 0x41;
    public final static byte TLV_TYPE_EPHIMERAL_STATE  = (byte) 0x42;
    public final static byte TLV_TYPE_MEMORY           = (byte) 0x43;
    public final static byte TLV_TYPE_COMPILEFLAGS     = (byte) 0x44;
    public final static byte TLV_TYPE_GITCOMMIT         = (byte) 0x45;
    public final static byte TLV_TYPE_EXAMPLEBACKDOOR   = (byte) 0x46;

    // Lengths
    public static final byte CARD_ID_LONG_LENGTH = (byte) 16;   // Length of unique card ID generated during applet install
    
    public static final short BASIC_ECC_LENGTH = (short) 32; // 32 => 256b ECC
    public static final short SHARE_BASIC_SIZE = BASIC_ECC_LENGTH;       
    public static final short SHARE_DOUBLE_SIZE = (short) (2 * SHARE_BASIC_SIZE);           // intermediate result of multiplication operation with shares (double bit length)
    public static final short SHARE_DOUBLE_SIZE_CARRY = (short) (SHARE_DOUBLE_SIZE + 1);    // double intermediate result + 1 byte carry  
    public static final short SECRET_SEED_SIZE = BASIC_ECC_LENGTH;
    
    
    public static final short MAX_QUORUMS = 1; // Maximum number of separate quorums this card can participate in
    
}
