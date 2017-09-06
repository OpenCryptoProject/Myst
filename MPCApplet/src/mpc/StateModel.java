package mpc;

import javacard.framework.ISOException;

/**
 *
 * @author Petr Svenda
 */
public class StateModel {
    private short STATE_KEYGEN = STATE_UNINITIALIZED;
    
    // Protocol state constants
    public static final byte STATE_UNINITIALIZED = (byte) -1;
    public static final byte STATE_KEYGEN_CLEARED = (byte) 0;
    public static final byte STATE_KEYGEN_PRIVATEGENERATED = (byte) 1;
    public static final byte STATE_KEYGEN_COMMITMENTSCOLLECTED = (byte) 2;
    public static final byte STATE_KEYGEN_SHARESCOLLECTED = (byte) 3;
    public static final byte STATE_KEYGEN_KEYPAIRGENERATED = (byte) 4;

    
    public static final short FNC_QuorumContext_GetXi               = (short) 0xf001;
    public static final short FNC_QuorumContext_GetYi               = (short) 0xf002;
    public static final short FNC_QuorumContext_Invalidate          = (short) 0xf003;
    public static final short FNC_QuorumContext_GetY                = (short) 0xf004;
    public static final short FNC_QuorumContext_GetShareCommitment  = (short) 0xf005;
    public static final short FNC_QuorumContext_SetYs               = (short) 0xf006;
    public static final short FNC_QuorumContext_SetShareCommitment  = (short) 0xf007;
    public static final short FNC_QuorumContext_GenerateExampleBackdooredKeyPair = (short) 0xf008;
    public static final short FNC_QuorumContext_InitAndGenerateKeyPair = (short) 0xf009;
    public static final short FNC_QuorumContext_GetState            = (short) 0xf00a;
    public static final short FNC_QuorumContext_Reset               = (short) 0xf00b;
    
    public static final short FNC_QuorumContext_Encrypt             = (short) 0xf00c;
    public static final short FNC_QuorumContext_DecryptShare        = (short) 0xf00d;
    public static final short FNC_QuorumContext_Sign_RetrieveRandomRi = (short) 0xf00e;
    public static final short FNC_QuorumContext_Sign                = (short) 0xf00f;
    
    
    public void CheckAllowedFunction(short requestedFnc) {
        CheckAllowedFunction(requestedFnc, STATE_KEYGEN);
    }
    
    public short MakeStateTransition(short newState) {
        STATE_KEYGEN = MakeStateTransition(STATE_KEYGEN, newState);
        return STATE_KEYGEN;
    }
    
    public short GetState() {
        return STATE_KEYGEN;
    }
    
    private static void CheckAllowedFunction(short requestedFnc, short currentState) {
        switch (requestedFnc) {
            case FNC_QuorumContext_GetXi:
                if (currentState == STATE_KEYGEN_KEYPAIRGENERATED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATE);
            case FNC_QuorumContext_GetY:
                if (currentState == STATE_KEYGEN_KEYPAIRGENERATED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATE);

            case FNC_QuorumContext_Reset:
                break; // any state is ok
 
            case FNC_QuorumContext_GetState:
                break; // any state is ok

            case FNC_QuorumContext_InitAndGenerateKeyPair:
                if (currentState == STATE_KEYGEN_CLEARED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATE);                
                
            case FNC_QuorumContext_GetShareCommitment:
                if (currentState == STATE_KEYGEN_PRIVATEGENERATED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATE);
                
            case FNC_QuorumContext_SetShareCommitment:
                if (currentState == STATE_KEYGEN_PRIVATEGENERATED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATE);

            case FNC_QuorumContext_SetYs:
                if (currentState == STATE_KEYGEN_COMMITMENTSCOLLECTED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATE);

            case FNC_QuorumContext_GetYi:
                if (currentState == STATE_KEYGEN_COMMITMENTSCOLLECTED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATE);
                
            case FNC_QuorumContext_Invalidate:
                break; // any state is ok

            case FNC_QuorumContext_Encrypt:
                 if (currentState == STATE_KEYGEN_KEYPAIRGENERATED) break;
                 ISOException.throwIt(Consts.SW_INCORRECTSTATE);
            case FNC_QuorumContext_DecryptShare:
                 if (currentState == STATE_KEYGEN_KEYPAIRGENERATED) break;
                 ISOException.throwIt(Consts.SW_INCORRECTSTATE);
            case FNC_QuorumContext_Sign_RetrieveRandomRi:
                 if (currentState == STATE_KEYGEN_KEYPAIRGENERATED) break;
                 ISOException.throwIt(Consts.SW_INCORRECTSTATE);
            case FNC_QuorumContext_Sign:
                 if (currentState == STATE_KEYGEN_KEYPAIRGENERATED) break;
                 ISOException.throwIt(Consts.SW_INCORRECTSTATE);
                
                
            default:
                ISOException.throwIt(Consts.SW_UNKNOWNFUNCTION);
       }
    }

    private static short MakeStateTransition(short currentState, short newState) {
        switch (newState) {
            case STATE_KEYGEN_CLEARED:
                break; // keypair can be cleared in any state
            case STATE_KEYGEN_PRIVATEGENERATED:
                if (currentState == STATE_KEYGEN_CLEARED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
            case STATE_KEYGEN_COMMITMENTSCOLLECTED:
                if (currentState == STATE_KEYGEN_PRIVATEGENERATED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
            case STATE_KEYGEN_SHARESCOLLECTED:
                if (currentState == STATE_KEYGEN_COMMITMENTSCOLLECTED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
            case STATE_KEYGEN_KEYPAIRGENERATED:
                if (currentState == STATE_KEYGEN_SHARESCOLLECTED) break;
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
            default:
                ISOException.throwIt(Consts.SW_UNKNOWNSTATE);
                
        }
        return newState;
    } 
}
