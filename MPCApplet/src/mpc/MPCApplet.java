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
    // TODO: Enable/disable propagation of private key to other quorum
    // TODO: Generate unique card key for signatures
    // TODO: Make unified structure of input data Sign(QuorumContextIndex | command apdu)_CardKey

    Bignat Sign_counter = null; // TODO: move into shared temp values
    QuorumContext[] m_quorums = null;
    
    public byte[] cardIDLong = null; // unique card ID generated during applet install
    
    CryptoOperations m_cryptoOps = null;

    public MPCApplet() {
        m_ecc = new ECConfig((short) 256);
        m_ecc.bnh.bIsSimulator = bIsSimulator;
        m_curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);

        ECPointBuilder.allocate(m_curve, m_ecc);
        ECPointBase.allocate(m_curve);
        m_cryptoOps = new CryptoOperations(m_ecc);
        
        m_quorums = new QuorumContext[Consts.MAX_QUORUMS];
        for (short i = 0; i < (short) m_quorums.length; i++) {
            m_quorums[i] = new QuorumContext(m_ecc, m_curve, m_cryptoOps);
        }
        
        Sign_counter = new Bignat((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, m_ecc.bnh);

        

        /*// Signing - older protocol with explicit hash
        CryptoObjects.EphimeralKey = new DKG();
        CryptoObjects.EphimeralKey_next = new DKG();
        */

        // Random card unique ID
        cardIDLong = new byte[Consts.CARD_ID_LONG_LENGTH];
        m_cryptoOps.randomData.generateData(cardIDLong, (short) 0, (short) cardIDLong.length);
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
        Quorum_ResetAll();
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
                // Card bootstrapping
                //
                case Consts.INS_PERSONALIZE_INITIALIZE:
                    // Generates initial secrets for this card and export public key 
                    Personalize_Init(apdu);
                    break;
                case Consts.INS_PERSONALIZE_SET_USER_AUTH_PUBKEY:
                    // Set public key later used to authorize requests
                    Personalize_SetUserAuthPubKey(apdu);
                    break;
                case Consts.INS_PERSONALIZE_CARDINFO:
                    Personalize_GetCardInfo(apdu);
                    break;
                    
                //
                // Quorum Management
                //
                case Consts.INS_QUORUM_SETUP_NEW:
                    // Includes this card into new quorum (QuorumContext[i])
                    Quorum_SetupNew(apdu);
                    break;
                case Consts.INS_QUORUM_REMOVE:
                    // Removes this card from existing quorum and cleanup quorum context (QuorumContext[i])
                    Quorum_Remove(apdu);
                    break;
                case Consts.INS_QUORUM_RESET:
                    // Reset all sensitive values in specified quorum (but keeps quorum settings) 
                    Quorum_Reset(apdu);
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
                // Key propagation to other quorums
                //    
                case Consts.INS_KEYPROPAGATION_RETRIEVE_PRIVKEY_SHARES:
                    KeyMove_RetrievePrivKeyShares(apdu);
                    break;
                case Consts.INS_KEYPROPAGATION_SET_PRIVKEY_SHARES:
                    KeyMove_SetPrivKeyShares(apdu);
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
                    Sign_RetrieveRandomRi(apdu);
                    break;
                case Consts.INS_SIGN:
                    Sign(apdu);
                    break;
                case Consts.INS_SIGN_GET_CURRENT_COUNTER:
                    Sign_GetCurrentCounter(apdu);
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
                        m_quorums[0].IS_BACKDOORED_EXAMPLE = true;
                        // Return the value of backdoored key
                        Util.arrayCopyNonAtomic(m_quorums[0].privbytes_backdoored, (short) 0, apdubuf, (short) 0, (short) m_quorums[0].privbytes_backdoored.length);
                        apdu.setOutgoingAndSend((short) 0, (short) m_quorums[0].privbytes_backdoored.length);
                    } else {
                        m_quorums[0].IS_BACKDOORED_EXAMPLE = false;
                    }
                    break;
                case Consts.INS_ADDPOINTS:
                    dataLen = apdu.setIncomingAndReceive();
                    len = m_cryptoOps.addPoint(apdubuf, ISO7816.OFFSET_CDATA, dataLen, apdubuf, (short) 0, p1);
                    apdu.setOutgoingAndSend((short) 0, len);
                    break;
                case Consts.BUGBUG_INS_KEYGEN_RETRIEVE_PRIVKEY:
                    dataLen = apdu.setIncomingAndReceive();
                    len = m_quorums[0].Getxi(apdubuf, (short) 0);
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
    void Quorum_SetupNew(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        
        // TODO: check authorization
        
        // TODO: extract quorum index
        m_quorums[0].NUM_PLAYERS = (short) (apdubuf[ISO7816.OFFSET_P1] & 0xff);
        m_quorums[0].CARD_INDEX_THIS = (short) (apdubuf[ISO7816.OFFSET_P2] & 0xff);

        // removed, requires explicit keygen operation CryptoObjects.KeyPair.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, true, false);
        //CryptoObjects.EphimeralKey.Reset(Parameters.NUM_PLAYERS, Parameters.CARD_INDEX_THIS, false, true);
        
        m_cryptoOps.randomData.generateData(m_quorums[0].secret_seed, (short) 0, Consts.SHARE_BASIC_SIZE); // Utilized later during signature protocol in Sign() and Gen_R_i()
        if (m_quorums[0].IS_BACKDOORED_EXAMPLE) {
            Util.arrayFillNonAtomic(m_quorums[0].secret_seed, (short) 0, Consts.SHARE_BASIC_SIZE, (byte) 0x33);
        }
        m_quorums[0].SETUP = true; // Ok, done
        
        // TODO: set state
    }
    
    void Quorum_Remove(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: check authorization
        
        // TODO: clear all forum sensitive values
        Quorum_Reset(null); // temporary call to legacy reset function

        // TODO: mark context free for next Quorum_SetupNew() call
        // TODO: set state
    }    
    

    void Quorum_Reset(APDU apdu) {
        // TODO: check authorization
        m_quorums[0].Reset();
        // Restore proper value of modulo_Bn (was erased during the card's reset)
        m_cryptoOps.modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
        m_cryptoOps.aBn.set_from_byte_array((short) (m_cryptoOps.aBn.length() - (short) CryptoOperations.r_for_BigInteger.length), CryptoOperations.r_for_BigInteger, (short) 0, (short) CryptoOperations.r_for_BigInteger.length);
    }
    void Quorum_ResetAll() {
        // TODO: reset all quorums from QuorumContext[]
        Quorum_Reset(null); // temporary call to legacy reset function
    }

    void Personalize_Init(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: check state
        // TODO: check authorization
        // TODO: generate card long-term signature key
        // TODO: clear QuorumContext[] 
        // TODO: change state
        // TODO: export card public info
    }
    
    void Personalize_SetUserAuthPubKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: check state
        // TODO: set long-term authorization key for subsequent operations
        // TODO: change state
        // TODO: export card public info
    }    
        
            
    void Personalize_GetCardInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short offset = 0;

        buffer[offset] = Consts.TLV_TYPE_CARDUNIQUEDID;
        offset++;
        Util.setShort(buffer, offset, (short) cardIDLong.length);
        offset += 2;
        Util.arrayCopyNonAtomic(cardIDLong, (short) 0, buffer, offset, (short) cardIDLong.length);
        offset += cardIDLong.length;

        buffer[offset] = Consts.TLV_TYPE_KEYPAIR_STATE;
        offset++;
        Util.setShort(buffer, offset, (short) 2);
        offset += 2;
        Util.setShort(buffer, offset, m_quorums[0].getState()); // TODO: read states from all quorums
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
        Util.setShort(buffer, offset, Consts.MAX_NUM_PLAYERS);
        offset += 2;
        buffer[offset] = m_quorums[0].PLAYERS_IN_RAM ? (byte) 1 : (byte) 0;
        offset++;
        buffer[offset] = Consts.COMPUTE_Y_ONTHEFLY ? (byte) 1 : (byte) 0;
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
        buffer[offset] = m_quorums[0].IS_BACKDOORED_EXAMPLE ? (byte) 1 : (byte) 0;
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
        m_quorums[0].Reset(m_quorums[0].NUM_PLAYERS, m_quorums[0].CARD_INDEX_THIS, true);        
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
        len = m_quorums[0].GetHash(apdubuf, (short) 0);
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
        m_quorums[0].SetHash(apdubuf[ISO7816.OFFSET_P1], apdubuf, ISO7816.OFFSET_CDATA, len);
        
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
        len = m_quorums[0].GetYi(apdubuf, (short) 0);
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
        m_quorums[0].SetYs(apdubuf[ISO7816.OFFSET_P1], apdubuf, ISO7816.OFFSET_CDATA, len);
        
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
        
        len = m_quorums[0].GetY().getW(apdubuf, (short) 0);
        
        // TODO: sign output data (if not signed later by host)
        // TODO: Switch into next state

        apdu.setOutgoingAndSend((short) 0, len);
    }    
    
    /**
     * Each member qi of Q1 then splits its secret xi in |Q2 | shares and
     * distributes them to the individual members of Q2. To do that qi follows
     * the secret sharing method shown in Algorithm 4.8. However, any t -of-t
     * secret sharing schemes proposed in the literature would do.
     * @param apdu 
     */
    void KeyMove_RetrievePrivKeyShares(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: Check state
        // TODO: split y into shares for other quorum
        // TODO: Switch into next state
        apdu.setOutgoingAndSend((short) 0, len);
    }    
    /**
     * Once each member of Q2 receives |Q1 | shares, which they then combine to
     * retrieve their share of the secret corresponding to y. Each member of Q2
     * can retrieve its share by summing the incoming shares, modulo p (the
     * prime provided in the domain parameters T ). An additional benefit of
     * such a scheme is that Q1 and Q2 may have different sizes. It should be
     * also noted that a naive approach of having each member of q1 send their
     * share of x to a member of q2 is insecure, as malicious members from q1
     * and q2 can then collude to reconstruct the public key.
     * @param apdu 
     */
    void KeyMove_SetPrivKeyShares(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // TODO: Check state
        // TODO: Combine all shares to restore secret key y
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
        dataLen = m_cryptoOps.Encrypt(m_quorums[0], apdubuf, ISO7816.OFFSET_CDATA, apdubuf, apdubuf[ISO7816.OFFSET_P1]);
        apdu.setOutgoingAndSend((short) 0, dataLen);
    }
    
    /**
     * All KeyGen_xxx executed before
     * @param apdu 
     */
    void DecryptData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        dataLen = m_cryptoOps.DecryptShare(m_quorums[0], apdubuf, ISO7816.OFFSET_CDATA, apdubuf, apdubuf[ISO7816.OFFSET_P1]);
        apdu.setOutgoingAndSend((short) 0, dataLen);
    }
    
    /**
     * Host queries the ICs for random group elements Ri j , where i is the id
     * of the IC and j an increasing request counter. Once such a request is
     * received, the IC verifies that the host is authorized to submit such a
     * request and then applies the keyed pseudorandom function on the index j
     * to compute ri, j = PRFs (j). The IC then uses ri, j to generate a
     * group element (EC Point) Ri j = ri, j · G, which is then returned to
     * the host.
     */
    void Sign_RetrieveRandomRi(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        
        // TODO: Check for strictly increasing request counter
        
        dataLen = m_cryptoOps.Gen_R_i(m_cryptoOps.shortToByteArray(apdubuf[ISO7816.OFFSET_P1]), m_quorums[0].secret_seed, apdubuf);
        apdu.setOutgoingAndSend((short) 0, dataLen);
    }  
    
    /** 
     * The signing phase starts with the host sending a Sign request
     * to all ICs . Such a request includes the hash of the plaintext
     * Hash(m), the index of the round j, and the random group element Rj
     * corresponding to the round. Each IC then first verifies that the host has
     * the authorization to submit queries ( and that the specific j has not
     * been already used . The latter check on j is to prevent attacks that
     * aim to either leak the private key or to allow the adversary to craft new
     * signatures from existing ones. If these checks are successful, the IC
     * executes Algorithm 4.7 and generates its signature share. The
     * signature share (σi, j , ϵj ) is then sent to the host.
     * @param apdu 
     */
    void Sign(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // TODO: Check authorization to ask for signs 
        // TODO: Check for strictly increasing request counter
        
        Sign_counter.from_byte_array((short) 2, (short) 0, m_cryptoOps.shortToByteArray((short) (apdubuf[ISO7816.OFFSET_P1] & 0xff)), (short) 0);

        dataLen = m_cryptoOps.Sign(m_quorums[0], Sign_counter, apdubuf, (short) (ISO7816.OFFSET_CDATA), dataLen, apdubuf, (short) 0, apdubuf[ISO7816.OFFSET_P2]);
        apdu.setOutgoingAndSend((short) 0, dataLen); //Send signature share 
    }
    
    /** 
     * Returns current signature counter expected for next signature round
     * @param apdu 
     */
    void Sign_GetCurrentCounter(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        dataLen = m_quorums[0].signature_counter.copy_to_buffer(apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, dataLen); //Send signature share 
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
