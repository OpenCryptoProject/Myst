package mpc;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class QuorumContext {
    private MPCCryptoOps cryptoOps = null;

    public short CARD_INDEX_THIS = 0;   // index of player realised by this card
    public short NUM_PLAYERS = 0;       // current number of players

    class Player {
        public boolean bYsValid = false;            // Is player's share (Ys) currently valid?
        public byte[] YsCommitment = null;          // Value of comitment of player's share  (hash(Ys))
        public boolean bYsCommitmentValid = false;  // Is comitment currently valid?
    }
    private Player[] players = null;                // contexts for all protocol participants (including this card)
            
    // Signing
    public Bignat signature_counter = null;
    public short signature_counter_short = 0;
    public byte[] signature_secret_seed = null; 

    // Distributed keypair generation share
    ECCurve theCurve = null;
    private KeyPair pair = null;
    private byte[] x_i_Bn = null;           // share xi, which is a randomly sampled element from Zn
    private byte[] this_card_Ys = null;     // Ys for this card (not stored in Player[] context as shares are combined on the fly) 
    private mpc.ECPointBase Y_EC_onTheFly = null; // aggregated Ys computed on the fly instead of in one shot once all shares are provided (COMPUTE_Y_ONTHEFLY)
    private short Y_EC_onTheFly_shares_count = 0; // number of public key shares already provided and combined during KeyGen_StorePublicKey
    private short num_commitments_count  = 0;     // number of stored commitments

    private StateModel state = null; // current state of the protocol run - some operations are not available in given state    
    
    
    public QuorumContext(ECConfig eccfg, ECCurve curve, MPCCryptoOps cryptoOperations) {
        cryptoOps = cryptoOperations;
        signature_counter = new Bignat(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        signature_secret_seed = new byte[Consts.SECRET_SEED_SIZE];
        
        theCurve = curve;
        this.pair = theCurve.newKeyPair(this.pair);
        x_i_Bn = JCSystem.makeTransientByteArray(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);

        players = new Player[Consts.MAX_NUM_PLAYERS];
        this_card_Ys = JCSystem.makeTransientByteArray(Consts.PUBKEY_YS_SHARE_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        for (short i = 0; i < Consts.MAX_NUM_PLAYERS; i++) {
            players[i] = new Player();
            if (Consts.PLAYERS_IN_RAM) {
                players[i].YsCommitment = JCSystem.makeTransientByteArray(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
            } else {
                players[i].YsCommitment = new byte[Consts.SHARE_BASIC_SIZE];
            }
        }

        Y_EC_onTheFly = ECPointBuilder.createPoint(SecP256r1.KEY_LENGTH);
        Y_EC_onTheFly.initializeECPoint_SecP256r1();

        state = new StateModel();
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
    }
    
    public void SetupNew(short numPlayers, short thisPlayerIndex) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_SetupNew);
        // Reset previous state
        Reset();
        
        if (numPlayers > Consts.MAX_NUM_PLAYERS || numPlayers < 1) {
            ISOException.throwIt(Consts.SW_TOOMANYPLAYERS);
        }
        if (thisPlayerIndex >= Consts.MAX_NUM_PLAYERS || thisPlayerIndex < 0) {
            ISOException.throwIt(Consts.SW_INVALIDPLAYERINDEX);
        }
        
        // Setup new state
        this.NUM_PLAYERS = numPlayers;
        this.CARD_INDEX_THIS = thisPlayerIndex;

        cryptoOps.randomData.generateData(signature_secret_seed, (short) 0, Consts.SHARE_BASIC_SIZE); // Utilized later during signature protocol in Sign() and Gen_R_i()
        if (Consts.IS_BACKDOORED_EXAMPLE) {
            Util.arrayFillNonAtomic(signature_secret_seed, (short) 0, Consts.SHARE_BASIC_SIZE, (byte) 0x33);
        }

        // TODO: store and setup user authorization keys (if provided)
        
        // Set state
        state.MakeStateTransition(StateModel.STATE_QUORUM_INITIALIZED);
        state.MakeStateTransition(StateModel.STATE_KEYGEN_CLEARED);
    }

    public void Reset() {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Reset);
        Invalidate(true);
        // Restore proper value of modulo_Bn (was possibly erased during the card's reset)
        cryptoOps.modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
        cryptoOps.aBn.set_from_byte_array((short) (cryptoOps.aBn.length() - (short) MPCCryptoOps.r_for_BigInteger.length), MPCCryptoOps.r_for_BigInteger, (short) 0, (short) MPCCryptoOps.r_for_BigInteger.length);
        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
    }
    
    short GetState() {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetState);
        return state.GetState();
    }

    /**
     * Initialize new quorum context and generates initial keypair for this card (Algorithm 4.1). 
     * Sets quorum size (numPlayers), id of this card. Prepares necessary initial structures.
     * @param numPlayers number of participants in this quorum
     * @param cardID participant index assigned to this card 
     * @param bPrepareDecryption if true, speedup engines for fast decryption are pre-prepared
     */
    public void InitAndGenerateKeyPair(boolean bPrepareDecryption) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_InitAndGenerateKeyPair);

        // Invalidate previously generated keypair  
        Invalidate(false);

        state.MakeStateTransition(StateModel.STATE_QUORUM_INITIALIZED);
        state.MakeStateTransition(StateModel.STATE_KEYGEN_CLEARED);
        
        pair.genKeyPair();

        if (Consts.IS_BACKDOORED_EXAMPLE) {
            // This branch demonstrates behavior of malicious attacker 
            GenerateExampleBackdooredKeyPair();
        } else {
            // Legitimate generation of key as per protocol by non-compromised participants
            ((ECPrivateKey) pair.getPrivate()).getS(x_i_Bn, (short) 0); // Algorithm 4.1, step 1.
        }

        // Add this card share into (future) aggregate key
        cryptoOps.placeholder.ScalarMultiplication(cryptoOps.GenPoint, x_i_Bn, this_card_Ys); // yG Algorithm 4.1, step 2.
        Y_EC_onTheFly.setW(this_card_Ys, (short) 0, (short) this_card_Ys.length);
        Y_EC_onTheFly_shares_count++;   // share for this card is included
        num_commitments_count = 1;      // share for this card is included
        // Update stored x_i properties
        players[CARD_INDEX_THIS].bYsValid = true;
        // Compute commitment, Algorithm 4.1, step 3.
        cryptoOps.md.reset();
        cryptoOps.md.doFinal(this_card_Ys, (short) 0, (short) this_card_Ys.length, players[CARD_INDEX_THIS].YsCommitment, (short) 0);
        players[CARD_INDEX_THIS].bYsCommitmentValid = true;

        // Pre-prepare engine for faster Decrypt later
        if (bPrepareDecryption) {
            if (ECPointBase.ECMultiplHelperDecrypt != null) { // Use prepared engine - cards with native support for EC
                ECPointBase.disposable_privDecrypt.setS(x_i_Bn, (short) 0, (short) x_i_Bn.length);
                ECPointBase.ECMultiplHelperDecrypt.init(ECPointBase.disposable_privDecrypt);
            }
        }
        state.MakeStateTransition(StateModel.STATE_KEYGEN_PRIVATEGENERATED);
        
        // In extreme case, quorum is of size 1 and final key is generated
        if (Y_EC_onTheFly_shares_count == NUM_PLAYERS) {
            state.MakeStateTransition(StateModel.STATE_KEYGEN_KEYPAIRGENERATED);
        }
    }
    
    public final byte[] privbytes_backdoored = {(byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55, (byte) 0x55};
    /**
     * Generates intentionally insecure private key to demonstrate behaviour when 
     * some participants are malicious. Private key bytes are all 0x55 ... 0x55
     */
    void GenerateExampleBackdooredKeyPair() {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GenerateExampleBackdooredKeyPair);
        // If enabled, key is not generated randomly as required per protocol, but fixed to vulnerable value instead
        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        ECPrivateKey priv = (ECPrivateKey) pair.getPrivate();

        // Set "backdoored" (known) private key - all 0x55 ... 0x55
        priv.setS(privbytes_backdoored, (short) 0, (short) privbytes_backdoored.length);
        ((ECPrivateKey) pair.getPrivate()).getS(x_i_Bn, (short) 0);
        // Compute and set corresponding public key (to backdoored private one)
        cryptoOps.placeholder.ScalarMultiplication(cryptoOps.GenPoint, privbytes_backdoored, cryptoOps.tmp_arr);
        pub.setW(cryptoOps.tmp_arr, (short) 0, (short) 65);
    }

    public short RetrieveCommitment(byte[] array, short offset) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_RetrieveCommitment);
        if (players[CARD_INDEX_THIS].bYsCommitmentValid) {
            Util.arrayCopyNonAtomic(players[CARD_INDEX_THIS].YsCommitment, (short) 0, array, offset, (short) players[CARD_INDEX_THIS].YsCommitment.length);
            return (short) players[CARD_INDEX_THIS].YsCommitment.length;
        } else {
            ISOException.throwIt(Consts.SW_INVALIDCOMMITMENT);
            return (short) -1;
        }
    }

    // State 0
    public void StoreCommitment(short id, byte[] commitment, short commitmentOffset, short commitmentLength) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_StoreCommitment);

        if (id < 0 || id == CARD_INDEX_THIS || id >= NUM_PLAYERS) {
            ISOException.throwIt(Consts.SW_INVALIDPLAYERINDEX);
        }
        if (commitmentLength != players[id].YsCommitment.length) {
            ISOException.throwIt(Consts.SW_INVALIDCOMMITMENTLENGTH);
        }
        if (players[id].bYsCommitmentValid) {
            // commitment already stored
            ISOException.throwIt(Consts.SW_COMMITMENTALREADYSTORED);
        }
        else {
            Util.arrayCopyNonAtomic(commitment, commitmentOffset, players[id].YsCommitment, (short) 0, commitmentLength);
            players[id].bYsCommitmentValid = true;
            num_commitments_count++;

            if (num_commitments_count == NUM_PLAYERS) {
                // All commitments were collected, allow for export of this card share
                state.MakeStateTransition(StateModel.STATE_KEYGEN_COMMITMENTSCOLLECTED);  
            }
            
        }
    }

    /** 
     * Sets public key share of other participant after verification of commitment match.
     * @param id    index of target participant
     * @param Y     buffer with target participant share
     * @param YOffset start offset within Y
     * @param YLength length of share
     */
    public void SetYs(short id, byte[] Y, short YOffset, short YLength) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_SetYs);

        if (id < 0 || id == CARD_INDEX_THIS || id >= NUM_PLAYERS) {
            ISOException.throwIt(Consts.SW_INVALIDPLAYERINDEX);
        }
        if (players[id].bYsValid) {
            ISOException.throwIt(Consts.SW_SHAREALREADYSTORED);
        }
        if (id == CARD_INDEX_THIS) {
            ISOException.throwIt(Consts.SW_INVALIDPLAYERINDEX);
        }
        // Verify against previously stored hash
        // TODO: if commitment check fails, terminate protocol and reset to intial state (and return error)
        if (!players[id].bYsCommitmentValid) {
            ISOException.throwIt(Consts.SW_INVALIDCOMMITMENT);
        }
        if (!cryptoOps.VerifyYsCommitment(Y, YOffset, YLength, players[id].YsCommitment)) {
            ISOException.throwIt(Consts.SW_INVALIDCOMMITMENT);
        }

        // Directly add into Y_EC_onTheFly, no storage into RAM
        ECPointBase.ECPointAddition(Y_EC_onTheFly, Y, YOffset, Y_EC_onTheFly);
        players[id].bYsValid = true;
        Y_EC_onTheFly_shares_count++;

        // check if shares for all players were included. If yes, change the state 
        if (Y_EC_onTheFly_shares_count == NUM_PLAYERS) {
            for (short i = 0; i < NUM_PLAYERS; i++) {
                if (!players[i].bYsValid) {
                    ISOException.throwIt(Consts.SW_INTERNALSTATEMISMATCH);
                }
            }
            state.MakeStateTransition(StateModel.STATE_KEYGEN_SHARESCOLLECTED);

            // The combination of shares is performed on the fly directly into Y_EC_onTheFly
            // If all contributed, Y_EC_onTheFly holds resulting combined public key
            state.MakeStateTransition(StateModel.STATE_KEYGEN_KEYPAIRGENERATED);
        }
    }

    /**
     * Returns this card public key share
     * @param commitmentBuffer output buffer where to store commitment
     * @param commitmentOffset start offset within target output buffer
     * @return 
     */
    public short GetYi(byte[] commitmentBuffer, short commitmentOffset) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetYi);

        if (state.GetState() == StateModel.STATE_KEYGEN_COMMITMENTSCOLLECTED) {
            if (players[CARD_INDEX_THIS].bYsValid) {
                Util.arrayCopyNonAtomic(this_card_Ys, (short) 0, commitmentBuffer, commitmentOffset, (short) this_card_Ys.length);
                return (short) this_card_Ys.length;
            } else {
                ISOException.throwIt(Consts.SW_INVALIDYSHARE);
            }
        } else {
            ISOException.throwIt(Consts.SW_INCORRECTSTATE);
        }
        return 0;
    }

    // State STATE_KEYGEN_KEYPAIRGENERATED
    public byte[] GetXi() { // Used to sign and decrypt
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetXi);

        return x_i_Bn;
    }

    public short GetXi(byte[] array, short offset) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetXi);
        
        Util.arrayCopyNonAtomic(x_i_Bn, (short) 0, array, offset, (short) x_i_Bn.length);
        return (short) x_i_Bn.length;
    }

    // State STATE_KEYGEN_KEYPAIRGENERATED
    public ECPointBase GetY() {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_GetY);
        return Y_EC_onTheFly;
    }

    public void Invalidate(boolean bEraseAllArrays) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Invalidate);

        if (bEraseAllArrays) {
            cryptoOps.randomData.generateData(cryptoOps.tmp_arr, (short) 0, (short) cryptoOps.tmp_arr.length);
            cryptoOps.randomData.generateData(x_i_Bn, (short) 0, (short) x_i_Bn.length);
            cryptoOps.randomData.generateData(signature_secret_seed, (short) 0, (short) signature_secret_seed.length);
            cryptoOps.randomData.generateData(this_card_Ys, (short) 0, (short) this_card_Ys.length);
            
        }
        // Invalidate all items
        for (short i = 0; i < Consts.MAX_NUM_PLAYERS; i++) {
            players[i].bYsCommitmentValid = false;
            players[i].bYsValid = false;
            if (bEraseAllArrays) {
                cryptoOps.randomData.generateData(players[i].YsCommitment, (short) 0, (short) players[i].YsCommitment.length);
            }
        }

        // TODO: clear Y_EC_onTheFly
        

        Y_EC_onTheFly_shares_count = 0;
        num_commitments_count = 0;
        signature_counter.zero();
        signature_counter_short = 0;

        state.MakeStateTransition(StateModel.STATE_QUORUM_CLEARED);
    }

    
    public short Encrypt(byte[] plaintext_arr, short plaintext_arr_offset, short plaintext_arr_len, byte[] outArray) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Encrypt);
        return cryptoOps.Encrypt(this, plaintext_arr, plaintext_arr_offset, plaintext_arr_len, outArray);
    }
    
    public short DecryptShare(byte[] c1_c2_arr, short c1_c2_arr_offset, short c1_c2_arr_len, byte[] outputArray) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_DecryptShare);
        return cryptoOps.DecryptShare(this, c1_c2_arr, c1_c2_arr_offset, outputArray);
    }
    
    public short Sign_RetrieveRandomRi(short counter, byte[] buffer) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign_RetrieveRandomRi);
        // Counter must be strictly increasing, check
        if (counter <= signature_counter_short) {
            ISOException.throwIt(Consts.SW_INVALIDCOUNTER);
        }
        signature_counter_short = counter;
        return cryptoOps.Gen_R_i(cryptoOps.shortToByteArray(signature_counter_short), signature_secret_seed, buffer);
    }
    
    public short Sign(Bignat i, byte[] Rn_plaintext_arr, short plaintextOffset, short plaintextLength, byte[] outputArray, short outputBaseOffset) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign);
        return cryptoOps.Sign(this, i, Rn_plaintext_arr, plaintextOffset, plaintextLength, outputArray, outputBaseOffset);   
    }
    
    public short Sign_GetCurrentCounter(byte[] outputArray, short outputBaseOffset) {
        state.CheckAllowedFunction(StateModel.FNC_QuorumContext_Sign_GetCurrentCounter);
        return signature_counter.copy_to_buffer(outputArray, outputBaseOffset);
    }
        
    
    /**
     * Verify if caller is authorized to submit request for given operation 
     * Right now, no check is performed and request is always allowed
     * @param apdu  
     */
    public void VerifyCallerAuthorization(APDU apdu, short requestedFnc) {
        //state.CheckAllowedFunction(StateModel.FNC_QuorumContext_VerifyCallerAuthorization);
        // TODO: enable verification if required
    }
}
