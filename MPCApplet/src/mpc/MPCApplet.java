package mpc;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class MPCApplet extends Applet {

    static boolean bIsSimulator = false;
    static boolean bFixRandomInputs = false; // if true, predictable random numbers are used 

    ECConfig m_ecc;
    ECCurve m_curve;
    
    // TODO: Every card can participate in multiple quorums => QuorumContext[]. For preventive security reasons, number of QuorumContexts can be 1 => no overlapping of protocols
    // TODO: Every quorum can be executing different protocol (keygen, enc, dec, sign, rng) - allow only one running protocol at the time for given quorum
    // TODO: Pro

    public MPCApplet() {
        m_ecc = new ECConfig((short) 256);
        m_ecc.bnh.bIsSimulator = bIsSimulator;
        m_curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);

        ECPointBuilder.allocate(m_curve, m_ecc);
        ECPointBase.allocate(m_curve);
        CryptoOperations.allocate(m_ecc);
        Parameters.allocate();
        Utils.allocate();
        CryptoObjects.allocate(m_ecc);

        CryptoObjects.KeyPair = new DKG(m_curve);
        

        /*// Signing - older protocol with explicit hash
        CryptoObjects.EphimeralKey = new DKG();
        CryptoObjects.EphimeralKey_next = new DKG();
        */

        // Random card unique ID
        CryptoOperations.randomData.generateData(Parameters.cardIDLong, (short) 0, (short) Parameters.cardIDLong.length);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        if (bLength == 0) {
            bIsSimulator = true;
            new MPCApplet().register();
        } else {
            new MPCApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        }
    }

    public boolean select() {
        updateAfterReset();
        Reset();
        return true;
    }

    // ////////////////////////////////////////////////////////////////////////////////////

    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        if (buf[ISO7816.OFFSET_CLA] == Consts.CLA_MPC) {
            byte[] apdubuf = apdu.getBuffer();

            short p1 = (short) (apdubuf[ISO7816.OFFSET_P1] & 0x00FF);
            short p2 = (short) (apdubuf[ISO7816.OFFSET_P2] & 0x00FF);
            short len;
            short dataLen;

            switch (buf[ISO7816.OFFSET_INS]) {
                //
                // Card Management
                //
                case Consts.INS_STATUS:
                    getCardInfo(apdu);
                    break;
                case Consts.INS_SETUP:
                    Setup(p1, p2);
                    break;
                case Consts.INS_RESET:
                    Reset();
                    break;

                //    
                // Key Generation
                //
                case Consts.INS_KEYGEN_INIT:
                    KeyGen_Init(apdu);
                    break;
                case Consts.INS_KEYGEN_RETRIEVE_COMMITMENT:
                    KeyGen_RetrieveCommitment(apdu);
                    break;
                case Consts.INS_KEYGEN_STORE_COMMITMENT:
                    KeyGen_StoreCommitment(apdu);
                    break;
                case Consts.INS_KEYGEN_RETRIEVE_PUBKEY:
                    KeyGen_RetrievePublicKey(apdu);
                    break;
                case Consts.INS_KEYGEN_STORE_PUBKEY:
                    KeyGen_StorePublicKey(apdu);
                    break;
                case Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY:
                    KeyGen_RetrieveAggregatedPublicKey(apdu);
                    break;
                    
                    
                //    
                // Encrypt and decrypt
                //
                case Consts.INS_ENCRYPT:
                    EncryptData(apdu);
                    break;
                case Consts.INS_DECRYPT:
                    DecryptData(apdu);
                    break;

                //    
                // Signing
                //
                case Consts.INS_SIGN_RETRIEVE_RI:
                    dataLen = apdu.setIncomingAndReceive();
                    len = CryptoOperations.Gen_R_i(Utils.shortToByteArray(p1), CryptoObjects.secret_seed, apdubuf);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;

                case Consts.INS_SIGN:
                    dataLen = apdu.setIncomingAndReceive();
                    CryptoObjects.Sign_counter.from_byte_array((short) 2, (short) 0, Utils.shortToByteArray((short) (p1 & 0xff)), (short) 0);

                    len = CryptoOperations.Sign(CryptoObjects.Sign_counter, apdubuf, (short) (ISO7816.OFFSET_CDATA), dataLen, apdubuf, (short) 0, p2);
                    apdu.setOutgoingAndSend((short) 0, len); //Send signature share 
                    break;

                //    
                // Random number generation
                //
                case Consts.INS_GENERATE_RANDOM:
                    GenerateRandomData(apdu);
                    break;
                    
                    
                /*                    
                //    
                // Signing - older protocol with explicit hash
                //
                 case Consts.INS_SIGN_INIT:
                    CryptoObjects.EphimeralKey.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, false, true);
                    //CryptoObjects.EphimeralKey_next.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS); //Preloading
                    break;

                case Consts.INS_SIGN_RETRIEVE_HASH:
                    len = CryptoObjects.EphimeralKey.GetHash(apdubuf, (short) 0);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;
                case Consts.INS_SIGN_STORE_HASH:
                    CryptoObjects.EphimeralKey.SetHash(p1, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
                    break;
                case Consts.INS_SIGN_STORE_RI:
                    CryptoObjects.EphimeralKey.SetYs(p1, apdubuf, ISO7816.OFFSET_CDATA, dataLen);
                    break;

                case Consts.INS_SIGN_STORE_RI_N_HASH:
                    CryptoObjects.EphimeralKey.SetYs(p1, apdubuf, (short) ISO7816.OFFSET_CDATA, (short) Consts.SHARE_SIZE_CARRY_65);
                    CryptoObjects.EphimeralKey_next.SetHash(p1, apdubuf, (short) (ISO7816.OFFSET_CDATA + Consts.SHARE_SIZE_CARRY_65), (short) Consts.SHARE_SIZE_32);
                    break;

                case Consts.INS_SIGN_RETRIEVE_RI_N_HASH:
                    len = CryptoObjects.EphimeralKey.GetYi(apdubuf, (short) 0);
                    len = CryptoObjects.EphimeralKey_next.GetHash(apdubuf, Consts.SHARE_SIZE_CARRY_65);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;

                case Consts.BUGBUG_INS_SIGN_RETRIEVE_KI:
                    len = CryptoObjects.EphimeralKey.Getxi(apdubuf, (short) 0);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;
                case Consts.BUGBUG_INS_SIGN_RETRIEVE_R:
                    len = CryptoObjects.EphimeralKey.GetY().getW(apdubuf, (short) 0);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;
*/                 
                //    
                // DEBUG methods    
                //
                case Consts.INS_TESTRSAMULT:
                    break;
                case Consts.INS_TESTECC:
                    dataLen = apdu.setIncomingAndReceive();
                    TestNativeECC(apdu, dataLen);
                    break;

                case Consts.INS_SET_BACKDOORED_EXAMPLE:
                    // If p1 == 0x55, then set flag which will cause applet to behave as example backdoored one
                    if (p1 == (byte) 0x55) {
                        DKG.IS_BACKDOORED_EXAMPLE = true;
                        // Return the value of backdoored key
                        Util.arrayCopyNonAtomic(DKG.privbytes_backdoored, (short) 0, apdubuf, (short) 0, (short) DKG.privbytes_backdoored.length);
                        apdu.setOutgoingAndSend((short) 0, (short) DKG.privbytes_backdoored.length);
                    } else {
                        DKG.IS_BACKDOORED_EXAMPLE = false;
                    }
                    break;
                case Consts.INS_ADDPOINTS:
                    dataLen = apdu.setIncomingAndReceive();
                    len = CryptoOperations.addPoint(apdubuf, ISO7816.OFFSET_CDATA, dataLen, apdubuf, (short) 0, p1);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;
                case Consts.BUGBUG_INS_KEYGEN_RETRIEVE_PRIVKEY:
                    dataLen = apdu.setIncomingAndReceive();
                    len = CryptoObjects.KeyPair.Getxi(apdubuf, (short) 0);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;


                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }
    
    void updateAfterReset() {
        if (m_curve != null) {
            m_curve.updateAfterReset();
        }
        if (m_ecc != null) {
            m_ecc.refreshAfterReset();
            m_ecc.unlockAll();
        }
        if (m_ecc.bnh != null) {
            m_ecc.bnh.bIsSimulator = bIsSimulator;
        }
    }

    // ///////////////////////////////////////////////////////////////////
    // // Card Management functionality ////
    // ///////////////////////////////////////////////////////////////////
    void Setup(short p1, short p2) {
        Parameters.NUM_PLAYERS = p1;
        Parameters.CARD_INDEX_THIS = p2;

        CryptoObjects.KeyPair.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, true, false);
        //CryptoObjects.EphimeralKey.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, false, true);
        CryptoOperations.randomData.generateData(CryptoObjects.secret_seed, (short) 0, Consts.SHARE_BASIC_SIZE);
        if (DKG.IS_BACKDOORED_EXAMPLE) {
            Util.arrayFillNonAtomic(CryptoObjects.secret_seed, (short) 0, Consts.SHARE_BASIC_SIZE, (byte) 0x33);
        }
        Parameters.SETUP = true; // Ok, done
    }

    void Reset() {
        Parameters.Reset();
        CryptoObjects.Reset();
        // Restore proper value of modulo_Bn (was erased during the card's reset)
        CryptoOperations.modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
        CryptoOperations.aBn.set_from_byte_array((short) (CryptoOperations.aBn.length() - (short) CryptoOperations.r_for_BigInteger.length), CryptoOperations.r_for_BigInteger, (short) 0, (short) CryptoOperations.r_for_BigInteger.length);
    }

    void getCardInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short offset = 0;

        buffer[offset] = Consts.TLV_TYPE_CARDUNIQUEDID;
        offset++;
        Util.setShort(buffer, offset, (short) Parameters.cardIDLong.length);
        offset += 2;
        Util.arrayCopyNonAtomic(Parameters.cardIDLong, (short) 0, buffer, offset, (short) Parameters.cardIDLong.length);
        offset += Parameters.cardIDLong.length;

        buffer[offset] = Consts.TLV_TYPE_KEYPAIR_STATE;
        offset++;
        Util.setShort(buffer, offset, (short) 2);
        offset += 2;
        Util.setShort(buffer, offset, CryptoObjects.KeyPair.getState());
        offset += 2;

        buffer[offset] = Consts.TLV_TYPE_EPHIMERAL_STATE;
        offset++;
        Util.setShort(buffer, offset, (short) 2);
        offset += 2;
        //Util.setShort(buffer, offset, CryptoObjects.EphimeralKey.getState());
        offset += 2;

        // Available memory
        buffer[offset] = Consts.TLV_TYPE_MEMORY;
        offset++;
        Util.setShort(buffer, offset, (short) 6);
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
        offset += 2;
        Util.setShort(buffer, offset, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
        offset += 2;

        // Used compile-time switches
        buffer[offset] = Consts.TLV_TYPE_COMPILEFLAGS;
        offset++;
        Util.setShort(buffer, offset, (short) 4);
        offset += 2;
        Util.setShort(buffer, offset, Consts.MAX_N_PLAYERS);
        offset += 2;
        buffer[offset] = CryptoObjects.KeyPair.PLAYERS_IN_RAM ? (byte) 1 : (byte) 0;
        offset++;
        buffer[offset] = CryptoObjects.KeyPair.COMPUTE_Y_ONTHEFLY ? (byte) 1 : (byte) 0;
        offset++;

        // Git commit tag
        buffer[offset] = Consts.TLV_TYPE_GITCOMMIT;
        offset++;
        Util.setShort(buffer, offset, (short) 4);
        offset += 2;
        Util.arrayCopyNonAtomic(Consts.GIT_COMMIT_MANUAL, (short) 0, buffer, offset, (short) Consts.GIT_COMMIT_MANUAL.length);
        offset += (short) Consts.GIT_COMMIT_MANUAL.length;

        // Flag about example demonstartion of beckdoored behavior
        buffer[offset] = Consts.TLV_TYPE_EXAMPLEBACKDOOR;
        offset++;
        Util.setShort(buffer, offset, (short) 1);
        offset += 2;
        buffer[offset] = DKG.IS_BACKDOORED_EXAMPLE ? (byte) 1 : (byte) 0;
        offset += 1;

        apdu.setOutgoingAndSend((short) 0, offset);
    }

    /**
     * Set trusted hashes of public keys for all other cards that may eventually
     * take part in protocol Used to quickly verify provided player's public key
     * during the protocol run
     *
     * @param apdu
     */
    void SetTrustedPubKeyHashes(APDU apdu) {
        // TODO
    }
    
    /* 
    At the first step of the protocol, each member of Q runs Algorithm 4.1 and generates
     a triplet consisting of: 1) a share xi , which is a randomly sampled
     element from Zn, 2) an elliptic curve point Yi , and 3) a commitment
     to Yi denoted hi.
    */
    void KeyGen_Init(APDU apdu) {
        // TODO: Check state
        
        // Generate new triplet
        CryptoObjects.KeyPair.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, true, false);        
    }
    
    /**
     * Upon the generation of the triplet, the members perform a pairwise
     * exchange of their commitments. KeyGen_RetrieveCommitment returns commitment for this card
     * @param apdu 
     */
    void KeyGen_RetrieveCommitment(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: Check state

        // Obtain commitment for this card
        len = CryptoObjects.KeyPair.GetHash(apdubuf, (short) 0);
        // TODO: sign the commitment (if not signed later by host)
        
        // TODO: Switch into next state
        apdu.setOutgoingAndSend((short) 0, len);
    }    
    
    /**
     * Upon the generation of the triplet, the members perform a pairwise
     * exchange of their commitments by the end of which, they all hold a
     * set H = {h1,h2, ..,ht }. The commitment exchange terminates when |Hq | =
     * t ∀q ∈ Q
     * @param apdu 
     */
    void KeyGen_StoreCommitment(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();    
    
        // TODO: Check state
        
        // TODO: verify signature on commitment

        // Store provided commitment
        CryptoObjects.KeyPair.SetHash(apdubuf[ISO7816.OFFSET_P1], apdubuf, ISO7816.OFFSET_CDATA, len);
        
        // TODO: check for termination of store commitment phase 
    }
    
    /**
     * Another round of exchanges starts (KeyGen_RetrievePublicKey and KeyGen_StorePublicKey), this time for the shares of Yagg
     * The commitment exchange round (KeyGen_RetrieveCommitment and KeyGen_StoreCommitment) is of uttermost
     * importance as it forces the participants to commit to a share of Yagg,
     * before receiving the shares of others. This prevents attacks where an 
     * adversary first collects the shares of others, and then crafts its share so as to bias the final pair,
     * towards a secret key they know.
     * @param apdu 
     */
    void KeyGen_RetrievePublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: Check state
        
        // Obtain public key
        len = CryptoObjects.KeyPair.GetYi(apdubuf, (short) 0);
        // TODO: sign the commitment (if not signed later by host)
        // TODO: Switch into next state

        apdu.setOutgoingAndSend((short) 0, len);
    }
    
    /**
     * Verify the validity of Y’s elements against their previous commitments KeyGen_StoreCommitment().
     * If one or more commitments fail the verification then the member infers that an error (either intentional or
     * unintentional) occurred and the protocol is terminated.
     * @param apdu 
     */
    void KeyGen_StorePublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: Check state
        // TODO: verify signature on public key
        // Store provided public key
        CryptoObjects.KeyPair.SetYs(apdubuf[ISO7816.OFFSET_P1], apdubuf, ISO7816.OFFSET_CDATA, len);
        
        // TODO: if commitment check fails, terminate protocol and reset to intial state (and return error)

        // TODO: check for termination of store pubkeys phase 
    }    
    
    /** 
     * If all commitments are successfully verified, then the member executes
     * Algorithm 4.3 and returns the result to the remote host. Note
     * that it is important to return Yagg, as well as the individual shares Yi
     * , as this protects against integrity attacks, where malicious ICs return
     * a different share than the one they committed to during the protocol. 
     * Moreover, since Yi are shares of the public key, they are also
     * assumed to be public, and available to any untrusted party.
     */
    void KeyGen_RetrieveAggregatedPublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: Check state
        
        len = CryptoObjects.KeyPair.GetY().getW(apdubuf, (short) 0);
        
        // TODO: sign output data (if not signed later by host)
        // TODO: Switch into next state

        apdu.setOutgoingAndSend((short) 0, len);
    }    
    
    /**
     * For encryption, we use the Elliptic Curve ElGamal scheme 
     * (Algorithm 4.4). This operation does not use the secret key, and can be
     * performed directly on the host, or remotely by any party holding the
     * public key, hence there is no need to perform it in a distributed manner.
     * @param apdu 
     */
    void EncryptData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        dataLen = CryptoOperations.Encrypt(apdubuf, ISO7816.OFFSET_CDATA, apdubuf, apdubuf[ISO7816.OFFSET_P1]);
        apdu.setOutgoingAndSend((short) 0, dataLen);
    }
    
    /**
     * All KeyGen_xxx executed before
     * @param apdu 
     */
    void DecryptData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        dataLen = CryptoOperations.DecryptShare(apdubuf, ISO7816.OFFSET_CDATA, apdubuf, apdubuf[ISO7816.OFFSET_P1]);
        apdu.setOutgoingAndSend((short) 0, dataLen);
    }
    
    /**
     * The remote host submits a request for randomness to all actors
     * participating in the quorum. Subsequently, each actor independently
     * generates a random share bi , encrypts it with the public key of the
     * host, and signs the ciphertext with its private key. Once the host
     * receives all the shares, he combines them to retrieve the b and then uses
     * an one way function (e.g., SHA3-512) to convert it to a fixed length
     * string.
     */
    void GenerateRandomData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: Check state
        // TODO: Verify signature on request
        // TODO: Generate share
        // TODO: Encrypt share with host public key
        // TODO: Sign output share

        apdu.setOutgoingAndSend((short) 0, len);
    }    
    
    
    public final static byte[] xe_Bn_testInput1 = {
        (byte) 0x03, (byte) 0xBD, (byte) 0x28, (byte) 0x6B, (byte) 0x6A, (byte) 0x22, (byte) 0x1F, (byte) 0x1B,
        (byte) 0xFC, (byte) 0x08, (byte) 0xC6, (byte) 0xC5, (byte) 0xB0, (byte) 0x3F, (byte) 0x0B, (byte) 0xEA,
        (byte) 0x6C, (byte) 0x38, (byte) 0xBE, (byte) 0xBA, (byte) 0xCF, (byte) 0x20, (byte) 0x2A, (byte) 0xAA,
        (byte) 0xDF, (byte) 0xAC, (byte) 0xA3, (byte) 0x70, (byte) 0x38, (byte) 0x32, (byte) 0xF8, (byte) 0xCC,
        (byte) 0xE0, (byte) 0xA8, (byte) 0x70, (byte) 0x88, (byte) 0xE9, (byte) 0x17, (byte) 0x21, (byte) 0xA3,
        (byte) 0x4C, (byte) 0x8D, (byte) 0x0B, (byte) 0x97, (byte) 0x11, (byte) 0x98, (byte) 0x02, (byte) 0x46,
        (byte) 0x04, (byte) 0x56, (byte) 0x40, (byte) 0xA1, (byte) 0xAE, (byte) 0x34, (byte) 0xC1, (byte) 0xFB,
        (byte) 0x7D, (byte) 0xB8, (byte) 0x45, (byte) 0x28, (byte) 0xC6, (byte) 0x1B, (byte) 0xC6, (byte) 0xD0};

    void TestNativeECC(APDU apdu, short dataLen) {
        /*        
         byte[] buff = apdu.getBuffer();
         short pointSize = (short) (buff[(short) ISO7816.OFFSET_P2] & 0x00FF);
        
         if (buff[ISO7816.OFFSET_P1] == (byte) 0x01) {
         CryptoOperations.c1_EC.setW(buff, (short) ISO7816.OFFSET_CDATA, pointSize);
         CryptoOperations.c1_EC.AddPoint(buff, (short) (ISO7816.OFFSET_CDATA + pointSize), pointSize);
         short len = CryptoOperations.c1_EC.getW(buff, (short) 0);
         apdu.setOutgoingAndSend((short) 0, len);            
         }
         if (buff[ISO7816.OFFSET_P1] == (byte) 0x02) {
         CryptoOperations.c1_EC.setW(buff, (short) ISO7816.OFFSET_CDATA, pointSize);
         ECPointBase.disposable_priv.setS(buff, (short) (ISO7816.OFFSET_CDATA + pointSize), (short) (dataLen - pointSize));
         ECPointBase.ECMultiplHelper.init(ECPointBase.disposable_priv); // Set multiplier        
         short len = ECPointBase.ScalarMultiplication(CryptoOperations.c1_EC, ECPointBase.ECMultiplHelper, buff); 
         apdu.setOutgoingAndSend((short) 0, len);
         }   
         */
    }
}
