package mpc;

import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class DKG {
    boolean PLAYERS_IN_RAM = true;
    boolean COMPUTE_Y_ONTHEFLY = true;
    boolean IS_BACKDOORED_EXAMPLE = false; // if true, then applet will not follow protocol but generates backdoored applet instead
            
    // Static shared Helper objects
    static MessageDigest md = null;
    //static private ECPoint GenPoint = null;

    ECCurve theCurve = null;
    private KeyPair pair = null;
    private byte[] x_i_Bn = null;
    private byte[] copy_x_i_Bn = null;
    byte[] tmp_arr = null;
    private mpc.ECPointBase Y_EC = null;
    private mpc.ECPointBase Y_EC_onTheFly = null; // aggregated Ys computed on the fly instead of in one shot once all shares are provided (COMPUTE_Y_ONTHEFLY)
    private byte[] CARD_THIS_YS = null;   // Ys for this card  
    private short N_PLAYERS = -1;         // current number of players
    private short CARD_INDEX_THIS = -1;   // index of player realised by this card
    private Player[] players = null;      // contexts for all players
    private short players_shares_count = 0;
    private short times_x_used	= 0; //This should be erased, it's no longer needed.
    //private byte[] privbytes = {(byte)0xB3, (byte)0x46, (byte)0x67, (byte)0x55, (byte)0x18, (byte)0x08, (byte)0x46, (byte)0x23, (byte)0xBC, (byte)0x11, (byte)0x1C, (byte)0xC5, (byte)0x3F, (byte)0xF6, (byte)0x15, (byte)0xB1, (byte)0x52, (byte)0xA3, (byte)0xF6, (byte)0xD1, (byte)0x58, (byte)0x52, (byte)0x78, (byte)0x37, (byte)0x0F, (byte)0xA1, (byte)0xBA, (byte)0x0E, (byte)0xA1, (byte)0x60, (byte)0x23, (byte)0x7E};    
    public static final byte[] privbytes_backdoored = {(byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55};
    
    /*
     * 0 Publishes hash(Y_i) 1 Publishes hash(Y_i), Y_i 2 Publishes hash(Y_i),
     * Y_i, x_i, and Y -1 Error State (when hashes-pubs do not check out),
     * doesn't respond. Reset() is needed
     */
    // BUGBUG: Check thoroughly for all state transitions (automata-based programming)
    private short STATE = -1; // current state of the protocol run - some operations are not available in given state

    
    public DKG(ECCurve curve) {
        theCurve = curve;

        if (md == null) {
            //md = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        }
        //GenPoint = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT, (short) SecP256r1.KEY_LENGTH);
        //GenPoint.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
        this.pair = theCurve.newKeyPair(this.pair);
        x_i_Bn = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        copy_x_i_Bn = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        tmp_arr = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_CARRY_65, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        
        ///////////
        //Arrays//
        //////////
        players = new Player[Consts.MAX_N_PLAYERS];
        if (COMPUTE_Y_ONTHEFLY) {
            CARD_THIS_YS = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_CARRY_65, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        }
        for (short i = 0; i < Consts.MAX_N_PLAYERS; i++) {
            players[i] = new Player();
            if (PLAYERS_IN_RAM) {
                if (!COMPUTE_Y_ONTHEFLY) {
                    players[i].Ys = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_CARRY_65, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
                }
                players[i].hash = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
            } else {
                players[i].Ys = new byte[Consts.SHARE_SIZE_CARRY_65];
                players[i].hash = new byte[Consts.SHARE_SIZE_32];
            }
        }

        Y_EC = ECPointBuilder.createPoint(SecP256r1.KEY_LENGTH);
        Y_EC.initializeECPoint_SecP256r1();
        Y_EC_onTheFly = ECPointBuilder.createPoint(SecP256r1.KEY_LENGTH);
        Y_EC_onTheFly.initializeECPoint_SecP256r1();

        STATE = 0;
    }    
    
    short getState() {
        return STATE;        
    }
    // ///////////////////////////////////////////////////////////////////
    // // Crypto functionality ////
    // //////////////////////////////////////////////////////////////////
    // State 0
   // public final void Reset(short numPlayers, short cardID) {
   //     Reset(numPlayers, cardID, false);
   // }
    
    public final void Reset(short numPlayers, short cardID, boolean bPrepareDecryption, boolean bFastGen) {
        if (numPlayers > Consts.MAX_N_PLAYERS) {
            ISOException.throwIt(Consts.SW_TOOMANYPLAYERS);
        }
        
        Invalidate(false);       
        
        players_shares_count = 0;

        N_PLAYERS = numPlayers;
        CARD_INDEX_THIS = cardID;

        /* Gen x_i */
        
        if ((bFastGen==false) || (times_x_used==0)) {
	        pair.genKeyPair();
                
                if (IS_BACKDOORED_EXAMPLE) {
                    // This branch demonstrates behavior of malicious attacker 
                    // If enabled, key is not generated randomly as required per protocol, but fixed to vulnerable value instead
                    ECPublicKey pub = (ECPublicKey) pair.getPublic();
                    ECPrivateKey priv = (ECPrivateKey) pair.getPrivate();

                    // Set "backdoored" (known) private key - all 0x55 ... 0x55
                    priv.setS(privbytes_backdoored, (short) 0, (short) privbytes_backdoored.length);
                    ((ECPrivateKey) pair.getPrivate()).getS(x_i_Bn, (short) 0);
                    // Compute and set corresponding public key (to backdoored private one)
                    CryptoOperations.placeholder.ScalarMultiplication(SecP256r1.G, (short) 0, (short) SecP256r1.G.length, privbytes_backdoored, tmp_arr);
                    pub.setW(tmp_arr, (short) 0, (short) 65);
                }
                else {
                    // Legitimate generation of key as per protocol by non-compromised participants
                    ((ECPrivateKey) pair.getPrivate()).getS(x_i_Bn, (short) 0);
                }
	        
	        Util.arrayCopyNonAtomic(x_i_Bn, (short)0, copy_x_i_Bn, (short)0, (short)x_i_Bn.length);

        } else if ((bFastGen==true) && (times_x_used>0)){
	        //Gen HMAC from existing x_i_Bn
	        md.reset();
	        md.update(copy_x_i_Bn, (short)0, (short)copy_x_i_Bn.length); //secret
	        md.doFinal(x_i_Bn, (short) 0, (short) x_i_Bn.length, x_i_Bn, (short) 0); //and previous K(i)
        }
        
        times_x_used += 1;
        
        CryptoOperations.placeholder.ScalarMultiplication(SecP256r1.G, (short) 0, (short) SecP256r1.G.length, x_i_Bn, CARD_THIS_YS); // yG
        
        if (COMPUTE_Y_ONTHEFLY) {
            Y_EC_onTheFly.setW(CARD_THIS_YS, (short) 0, (short) CARD_THIS_YS.length);     
        }
        // Update stored x_i properties
        players[CARD_INDEX_THIS].bYsValid = true;
        players_shares_count++; // share for this card is included
        md.reset();
        md.doFinal(CARD_THIS_YS, (short) 0, Consts.SHARE_SIZE_CARRY_65, players[CARD_INDEX_THIS].hash, (short) 0);
        players[CARD_INDEX_THIS].bHashValid = true;

        // Pre-prepare engine for faster Decrypt later
        if (bPrepareDecryption) {
            ECPointBase.disposable_privDecrypt.setS(x_i_Bn, (short) 0, (short) x_i_Bn.length);
            if (ECPointBase.ECMultiplHelperDecrypt != null) { // BUGBUG jcarsim test
                ECPointBase.ECMultiplHelperDecrypt.init(ECPointBase.disposable_privDecrypt);
            }
        }
        STATE = 0;
    }    

    
    public void Copy(DKG AnotherDKG) {
        //this.PLAYERS_IN_RAM = AnotherDKG.PLAYERS_IN_RAM;
        //this.COMPUTE_Y_ONTHEFLY = AnotherDKG.COMPUTE_Y_ONTHEFLY;
        // BUGBUG: this is shallow copy only        
        this.pair = AnotherDKG.pair;
        this.x_i_Bn = AnotherDKG.x_i_Bn; 
        this.tmp_arr = AnotherDKG.tmp_arr;
        this.Y_EC = AnotherDKG.Y_EC;
        this.Y_EC_onTheFly = AnotherDKG.Y_EC_onTheFly;

        this.N_PLAYERS = AnotherDKG.N_PLAYERS;
        this.CARD_INDEX_THIS = AnotherDKG.CARD_INDEX_THIS;
        for (short i = 0; i < Parameters.NUM_PLAYERS; i++) {
        	this.players[i].Copy(AnotherDKG.players[i]);
        }
        this.players_shares_count = AnotherDKG.players_shares_count;
        
        this.STATE = AnotherDKG.STATE;

    }

    // State 0
    public byte[] GetHash() {
        if (players[CARD_INDEX_THIS].bHashValid) {
            return players[CARD_INDEX_THIS].hash;
        }
        else {
            return null;
        }
    }
    
    public short GetHash(byte[] array, short offset) {
        if (players[CARD_INDEX_THIS].bHashValid) {
            Util.arrayCopyNonAtomic(players[CARD_INDEX_THIS].hash, (short) 0, array, offset, (short) players[CARD_INDEX_THIS].hash.length);
            return (short) players[CARD_INDEX_THIS].hash.length;
        } else {
            return (short) -1;
        }
    }    

    // State 0
    public void SetHash(short id, byte[] hash, short hashOffset, short hashLength) {
        Util.arrayCopyNonAtomic(hash, hashOffset, players[id].hash, (short) 0, hashLength);
        players[id].bHashValid = true;
    }
    
    // State 0
    public void SetY(byte[] Y, short YOffset, short YLength) {    
    	Y_EC_onTheFly.setW(Y, YOffset, YLength);
    }
    
    public void SetYs(short id, byte[] Y, short YOffset, short YLength) {
        if (COMPUTE_Y_ONTHEFLY) {
            if (players[id].bYsValid) { ISOException.throwIt(Consts.SW_SHAREALREADYSTORED);}
            // Verify against previously stored hash
            if (!players[id].bHashValid) {ISOException.throwIt(Consts.SW_INVALIDHASH);}            
            if (!VerifyPair(Y, YOffset, YLength, players[id].hash)) {
                ISOException.throwIt(Consts.SW_INVALIDHASH);
            }
            
            // Directly add into Y_EC_onTheFly, no storage into RAM
            ECPointBase.ECPointAddition(Y_EC_onTheFly, Y, YOffset, Y_EC_onTheFly);
            players[id].bYsValid = true;
            players_shares_count++;

            if (players_shares_count == N_PLAYERS) {
                STATE = 2;
            }
        }
        else {
            Util.arrayCopyNonAtomic(Y, YOffset, players[id].Ys, (short) 0, YLength);
            players[id].bYsValid = true;

            // Ready to move to state 2?
            players_shares_count = 0;
            for (short i = 0; i < N_PLAYERS; i++) {
                if (players[i].bYsValid) {
                    players_shares_count += 1;
                }
            }

            if (players_shares_count == N_PLAYERS) {
                if (VerifyPairs() == true) {
                    STATE = 2;

                    // Compute aggregated Y
                    Y_EC.setW(players[0].Ys, (short) 0, (short) players[0].Ys.length); 
                    for (short i = 1; i < N_PLAYERS; i++) {
                        ECPointBase.ECPointAddition(Y_EC, players[i].Ys, (short) 0, Y_EC);
                    }

                    // Y_EC now contains added points from all players
                }
            }
        }
    }

    // State 1
    public byte[] GetYi() {
    	//If not on state 1 already:
    	if (STATE < 1) {
	    	// Ready to move to state 1?
	        short tmp_count = 0;
	        for (short i = 0; i < N_PLAYERS; i++) {
	            if (players[i].bHashValid) {
	                tmp_count += 1;
	            }
	        }
	
	        if (tmp_count == N_PLAYERS) {
	            STATE = 1;
	        }
    	}
    	
    	
    	if (STATE >= 1 && players[CARD_INDEX_THIS].bYsValid) {
            if (COMPUTE_Y_ONTHEFLY) {
                return CARD_THIS_YS;
            }
            else {
                return players[CARD_INDEX_THIS].Ys;
            }
            
        } else {
            return null;
        }
    }
    
    public short GetYi(byte[] array, short offset) {
    	//If not on state 1 already:
    	if (STATE < 1) {
	    	// Ready to move to state 1?
	        short tmp_count = 0;
	        for (short i = 0; i < N_PLAYERS; i++) {
	            if (players[i].bHashValid) {
	                tmp_count += 1;
	            }
	        }
	
	        if (tmp_count == N_PLAYERS) {
	            STATE = 1;
	        }
    	}
    	
        if (STATE >= 1) {
            if (players[CARD_INDEX_THIS].bYsValid) {
                Util.arrayCopyNonAtomic(CARD_THIS_YS, (short) 0, array, offset, (short) CARD_THIS_YS.length);
                return (short) CARD_THIS_YS.length;
            }
            else {ISOException.throwIt(Consts.SW_INVALIDYSHARE);}
        } else {
            ISOException.throwIt(Consts.SW_INCORRECTSTATE);
        }
        return 0;
    }

    // State 2
    public byte[] Getxi() { // Used to sign and decrypt
        if ((STATE >= 2)|| (Parameters.NUM_PLAYERS==1)) {
            return x_i_Bn;
        } else {
            ISOException.throwIt(Consts.SW_INCORRECTSTATE);
            return null;
        }
    }
    
    public short Getxi(byte[] array, short offset) {
        if ((STATE >= 2) || (Parameters.NUM_PLAYERS==1)) {
            Util.arrayCopyNonAtomic(x_i_Bn, (short) 0, array, offset, (short) x_i_Bn.length);
            return (short) x_i_Bn.length;
        } else {
            return (short) -1;
        }
    }

    // State 2
    public ECPointBase GetY() {
        if ((STATE >= 2) || (Parameters.NUM_PLAYERS==1)){
            if (COMPUTE_Y_ONTHEFLY) {
                return Y_EC_onTheFly;
            }
            else {
                return Y_EC;
            }
        } else {
            return null;
        }
    }

    // State -1
    public void Invalidate(boolean bEraseAllArrays) {
        // Invalidate all items
        //EC_Utils.initializeECPoint(Y_EC);
        //EC_Utils.initializeECPoint(Y_EC_onTheFly);
    	
        if (bEraseAllArrays) {
            Util.arrayFillNonAtomic(tmp_arr, (short) 0, (short) tmp_arr.length, (byte) 0);
            Util.arrayFillNonAtomic(x_i_Bn, (short) 0, (short) x_i_Bn.length, (byte) 0);
        }
        for (short i = 0; i < Consts.MAX_N_PLAYERS; i++) {
            players[i].bHashValid = false;
            players[i].bYsValid = false;
            if (bEraseAllArrays) {
                Util.arrayFillNonAtomic(players[i].hash, (short) 0, (short) players[i].hash.length, (byte) 0);
                if (players[i].Ys != null) {
                    Util.arrayFillNonAtomic(players[i].Ys, (short) 0, (short) players[i].Ys.length, (byte) 0);
                }
            }
        }   

        STATE = -1;
        players_shares_count = 0;
    }

    

    // State -1

    // /////////////////////////
    // Helper Functions
    // ////////////////////////
    private boolean VerifyPairs() {
        for (short i = 0; i < N_PLAYERS; i++) {
            if (!VerifyPair(i)) {
                return false;
            }
        }
        return true;
    }

    private boolean VerifyPair(short index) {
        if (!players[index].bHashValid || !players[index].bYsValid) {
            return false;
        } else {
            return VerifyPair(players[index].Ys, (short) 0, Consts.SHARE_SIZE_CARRY_65, players[index].hash);
        }
    }

    private boolean VerifyPair(byte[] Ys, short YsOffset, short YsLength, byte[] hash) {
        md.reset();
        md.doFinal(Ys, YsOffset, YsLength, tmp_arr, (short) 0);
        if (Util.arrayCompare(tmp_arr, (short) 0, hash,
                (short) 0, Consts.SHARE_SIZE_32) != 0) {
            return false;
        }
        else {
            return true;
        }
    }
    
    //Copy hashes from another DKG object
    public void CopyHashes(DKG PreLoadedDKG) {
   	
    	boolean bFoundInvalid = false;
	    for (short i = 0; i < Consts.MAX_N_PLAYERS; i++) {
	    	if (PreLoadedDKG.players[i].bHashValid==true) {
	    		Util.arrayCopyNonAtomic(PreLoadedDKG.players[i].hash, (short) 0, this.players[i].hash, (short)0, (short) PreLoadedDKG.players[i].hash.length);
	    		this.players[i].bHashValid = true;
	    	}else {
	    		bFoundInvalid = true;
	    	}
	    	
	    }
        
        // Ready to move to state 1?
        if (bFoundInvalid == false) {
            STATE = 1;
        }
    
    }
    
    
    
    
}
