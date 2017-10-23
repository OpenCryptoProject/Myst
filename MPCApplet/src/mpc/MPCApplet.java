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
    static boolean bIsSimulator = false;    // if true, applet is running in simulator. Detection Required for certain operations where simulator differs from real card

    ECConfig m_ecc;
    ECCurve m_curve;
    
    // TODO: Every card can participate in multiple quorums => QuorumContext[]. For preventive security reasons, number of QuorumContexts can be 1 => no overlapping of protocols
    // TODO: Every quorum can be executing different protocol (keygen, enc, dec, sign, rng) - allow only one running protocol at the time for given quorum
    // TODO: Enable/disable propagation of private key to other quorum
    // TODO: Generate unique card key for signatures
    // TODO: Make unified structure of input data Sign(QuorumContextIndex | command apdu)_CardKey
    // TODO: Unify response codes
    // TODO: Remove IS_BACKDOORED_EXAMPLE
    // TODO: remove boolean variables
    // TODO: consider unification of STATE_QUORUM_INITIALIZED and STATE_KEYGEN_CLEARED
    // TODO: Rename Bignat variables
    // TODO: Capture all exceptions in process() and reset state after several detected exceptions to prevent repeated attacks 
    // TODO: encrypt result of DecryptShare under host public key
    // TODO: unify all member attributes under m_xxx naming and camelCase
    
    public byte[] cardIDLong = null; // unique card ID generated during the applet install
    
    MPCCryptoOps m_cryptoOps = null;
    QuorumContext[] m_quorums = null;

    public MPCApplet() {
        m_ecc = new ECConfig((short) 256);
        m_ecc.bnh.bIsSimulator = bIsSimulator;
        m_curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);

        ECPointBuilder.allocate(m_curve, m_ecc);
        ECPointBase.allocate(m_curve);
        
        m_cryptoOps = new MPCCryptoOps(m_ecc);
        
        m_quorums = new QuorumContext[Consts.MAX_QUORUMS];
        for (short i = 0; i < (short) m_quorums.length; i++) {
            m_quorums[i] = new QuorumContext(m_ecc, m_curve, m_cryptoOps);
        }
        
        // Generate random unique card ID
        cardIDLong = new byte[Consts.CARD_ID_LONG_LENGTH];
        m_cryptoOps.randomData.generateData(cardIDLong, (short) 0, (short) cardIDLong.length);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // GP-compliant JavaCard applet registration
        if (bLength == 0) {
            // Simulator provides no install params
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
        byte[] apdubuf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        if (selectingApplet()) {
            return;
        }

        if (apdubuf[ISO7816.OFFSET_CLA] == Consts.CLA_MPC) {
            switch (apdubuf[ISO7816.OFFSET_INS]) {
                case Consts.INS_PERF_SETSTOP:
                    PM.m_perfStop = Util.makeShort(apdubuf[ISO7816.OFFSET_CDATA], apdubuf[(short) (ISO7816.OFFSET_CDATA + 1)]);
                    break;
                
                //
                // Card bootstrapping
                //
                case Consts.INS_PERSONALIZE_INITIALIZE:
                    // Generates initial secrets, set user authorization info and export card's public key 
                    Personalize_Init(apdu);
                    break;
/*                    
                case Consts.INS_PERSONALIZE_SET_USER_AUTH_PUBKEY:
                    // Set public key later used to authorize requests
                    Personalize_SetUserAuthPubKey(apdu);
                    break;
*/                    
                case Consts.INS_PERSONALIZE_GETCARDINFO:
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
                case Consts.INS_KEYPROPAGATION_RECONSTRUCT_PRIVATEKEY:
                    KeyMove_ReconstructPrivateKey(apdu);
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

    /**
     * Returns target quorum based on info from input apdu
     * @param apdubuf
     * @param paramsStartOffset
     * @return 
     */
    QuorumContext GetTargetQuorumContext(byte[] apdubuf, short paramsStartOffset) {
        short ctxIndex = Util.getShort(apdubuf, (short) (paramsStartOffset + Consts.PACKET_PARAMS_CTXINDEX_OFFSET));
        if (ctxIndex < 0 || ctxIndex >= (short) m_quorums.length) ISOException.throwIt(Consts.SW_INVALIDQUORUMINDEX);
        return m_quorums[ctxIndex];
    }
    
    short GetOperationParamsOffset(byte operationCode, APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.getIncomingLength();
        // Check correctness of basic structure and expected operation
        short offset = ISO7816.OFFSET_CDATA;
        if (apdubuf[offset] != Consts.TLV_TYPE_MPCINPUTPACKET) ISOException.throwIt(Consts.SW_INVALIDPACKETSTRUCTURE);
        offset++;
        short packetLen = Util.getShort(apdubuf, offset);
        if (packetLen < 1 || packetLen > dataLen) ISOException.throwIt(Consts.SW_INVALIDPACKETSTRUCTURE); // at least 1 byte of packet content required for operationCode
        offset += 2;
        if ((byte) apdubuf[offset] != (byte) operationCode) ISOException.throwIt(Consts.SW_INVALIDPACKETSTRUCTURE);

        return offset;
    }
    
    void Quorum_SetupNew(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        
        short paramsOffset = GetOperationParamsOffset(Consts.INS_QUORUM_SETUP_NEW, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_SetupNew);
        // Extract function parameters
        short numPlayers = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SETUPNEWQUORUM_NUMPLAYERS_OFFSET));
        short thisPlayerIndex = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SETUPNEWQUORUM_THISPLAYERINDEX_OFFSET));
        quorumCtx.SetupNew(numPlayers, thisPlayerIndex);
    }
    
    void Quorum_Remove(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        short paramsOffset = GetOperationParamsOffset(Consts.INS_QUORUM_REMOVE, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_GenerateRandomData);
        
        quorumCtx.Reset();

        // TODO: mark context free for next Quorum_SetupNew() call
    }    
    

    void Quorum_Reset(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        
        short paramsOffset = GetOperationParamsOffset(Consts.INS_QUORUM_RESET, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_Reset);
        // Reset target quorum context    
        quorumCtx.Reset();
    }
    
    /**
     * Reset all quorum from QuorumContext[]
     * @param apdu 
     */
    void Quorum_ResetAll() {
        for (short i = 0; i < (short) m_quorums.length; i++) {
            // TODO: shall we verify before reset? m_quorums[i].VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_Reset);
            m_quorums[i].Reset(); 
        }
    }

    void Personalize_Init(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.getIncomingLength();

        // TODO: check state
        // TODO: check authorization
        // TODO: generate card long-term signature key
        // TODO: clear QuorumContext[] 
        // TODO: change state
        // TODO: export card public info
    }
    
    void Personalize_SetUserAuthPubKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.getIncomingLength();

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
        Util.setShort(buffer, offset, m_quorums[0].GetState()); // TODO: read states from all quorums
        offset += 2;

        buffer[offset] = Consts.TLV_TYPE_EPHIMERAL_STATE;
        offset++;
        Util.setShort(buffer, offset, (short) 2);
        offset += 2;
        //Util.setShort(buffer, offset, CryptoObjects.EphimeralKey.getState()); // TODO: read states from all quorums
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
        buffer[offset] = Consts.PLAYERS_IN_RAM ? (byte) 1 : (byte) 0;
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
        buffer[offset] = Consts.IS_BACKDOORED_EXAMPLE ? (byte) 1 : (byte) 0;
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
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_INIT, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_InitAndGenerateKeyPair);
        // Generate new triplet
        quorumCtx.InitAndGenerateKeyPair(true);        
    }
    
    /**
     * Upon the generation of the triplet, the members perform a pairwise
     * exchange of their commitments. KeyGen_RetrieveCommitment returns commitment for this card
     * @param apdu 
     */
    void KeyGen_RetrieveCommitment(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_RETRIEVE_COMMITMENT, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_RetrieveCommitment);
        // Obtain commitment for this card
        short len = quorumCtx.RetrieveCommitment(apdubuf, (short) 0);
        // TODO: sign the commitment (if not signed later by host)
        
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
        short len = apdu.getIncomingLength();
        
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_STORE_COMMITMENT, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_StoreCommitment);
        
        // Store provided commitment
        short playerId = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_PLAYERID_OFFSET));
        short commitmentLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_COMMITMENTLENGTH_OFFSET));
        quorumCtx.StoreCommitment(playerId, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTORECOMMITMENT_COMMITMENT_OFFSET), commitmentLen);
    }
    
    /**
     * Another round of exchanges starts (KeyGen_RetrievePublicKey and KeyGen_StorePublicKey), this time for the shares of Yagg
     * The commitment exchange round (KeyGen_RetrieveCommitment and KeyGen_StoreCommitment) is of uttermost
     * importance as it forces the participants to commit to a share of Yagg, before receiving the shares of others. 
     * This prevents attacks where an adversary first collects the shares of others, and then crafts its share so as to bias the final pair,
     * towards a secret key they know.
     * @param apdu 
     */
    void KeyGen_RetrievePublicKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_RETRIEVE_PUBKEY, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_GetYi);
        // Retrieve public key
        short len = quorumCtx.GetYi(apdubuf, (short) 0);
        // TODO: sign the commitment (if not signed later by host)

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
        short len = apdu.getIncomingLength();

        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_STORE_PUBKEY, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_SetYs);
        // Store provided public key 
        short playerId = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_PLAYERID_OFFSET));
        short pubKeyLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_PUBKEYLENGTH_OFFSET));
        quorumCtx.SetYs(playerId, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_KEYGENSTOREPUBKEY_PUBKEY_OFFSET), pubKeyLen);
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
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_GetY);
        // Retrieve aggregated pubic key
        short len = quorumCtx.GetY().getW(apdubuf, (short) 0);
        // TODO: sign output data (if not signed later by host)

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
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYPROPAGATION_RETRIEVE_PRIVKEY_SHARES, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        // TODO: Check state
        // TODO: split y into shares for other quorum
        // TODO: Switch into next state
        // apdu.setOutgoingAndSend((short) 0, len);
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
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYPROPAGATION_SET_PRIVKEY_SHARES, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        // TODO: Check state
        // TODO: Combine all shares to restore secret key y
        // TODO: Switch into next state
        //apdu.setOutgoingAndSend((short) 0, len);
    }
    
    void KeyMove_ReconstructPrivateKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_KEYPROPAGATION_RECONSTRUCT_PRIVATEKEY, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);

        // TODO: Check state
        // TODO: Combine all shares to restore secret key y
        // TODO: Switch into next state
        //apdu.setOutgoingAndSend((short) 0, len);
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
        short paramsOffset = GetOperationParamsOffset(Consts.INS_ENCRYPT, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_Encrypt);
        short dataLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_ENCRYPT_DATALENGTH_OFFSET));
        dataLen = quorumCtx.Encrypt(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_ENCRYPT_DATA_OFFSET), dataLen, apdubuf);
        apdu.setOutgoingAndSend((short) 0, dataLen);
    }
    
    /**
     * Distributed data decryption (Algorithm 4.5). All KeyGen_xxx must be executed before.
     * @param apdu 
     */
    void DecryptData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_DECRYPT, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization - is caller allowed to ask for decryption? 
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_DecryptShare);

        short dataLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_DECRYPT_DATALENGTH_OFFSET));
        dataLen = quorumCtx.DecryptShare(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_DECRYPT_DATA_OFFSET), dataLen, apdubuf);
        // TODO: encrypt result under host public key and sign by card's key
        apdu.setOutgoingAndSend((short) 0, dataLen);
    }
    
    /**
     * Part of distributed signature scheme (Algorithm 4.7). All KeyGen_xxx must be executed
     * before. 
     * @apdu input apdu
     */
    void Sign_RetrieveRandomRi(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_SIGN_RETRIEVE_RI, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_Sign_RetrieveRandomRi);
        
        short counter = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGNRETRIEVERI_COUNTER_OFFSET));
        short dataLen = quorumCtx.Sign_RetrieveRandomRi(counter, apdubuf);
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
        short paramsOffset = GetOperationParamsOffset(Consts.INS_SIGN, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_Sign);

        // TODO: Check for strictly increasing request counter
        
        m_cryptoOps.temp_sign_counter.from_byte_array((short) 2, (short) 0, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_COUNTER_OFFSET));
        short dataLen = Util.getShort(apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_DATALENGTH_OFFSET));
        dataLen = quorumCtx.Sign(m_cryptoOps.temp_sign_counter, apdubuf, (short) (paramsOffset + Consts.PACKET_PARAMS_SIGN_DATA_OFFSET), dataLen, apdubuf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, dataLen); //Send signature share 
    }
    
    /** 
     * Returns current signature counter expected for next signature round
     * @param apdu 
     */
    void Sign_GetCurrentCounter(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short paramsOffset = GetOperationParamsOffset(Consts.INS_SIGN_GET_CURRENT_COUNTER, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_Sign_GetCurrentCounter);
        // Send signature share 
        short dataLen = quorumCtx.Sign_GetCurrentCounter(apdubuf, (short) 0);
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
        short paramsOffset = GetOperationParamsOffset(Consts.INS_GENERATE_RANDOM, apdu);
        // Parse incoming apdu to obtain target quorum context
        QuorumContext quorumCtx = GetTargetQuorumContext(apdubuf, paramsOffset);
        // Verify authorization
        quorumCtx.VerifyCallerAuthorization(apdu, StateModel.FNC_QuorumContext_GenerateRandomData);
        
        // TODO: Check state
        // TODO: Verify signature on request
        // TODO: Generate share
        // TODO: Encrypt share with host public key
        // TODO: Sign output share

        //apdu.setOutgoingAndSend((short) 0, len);
    }    
}
