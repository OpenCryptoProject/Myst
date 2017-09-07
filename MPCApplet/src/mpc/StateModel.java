package mpc;

import javacard.framework.ISOException;

/**
 *
 * @author Petr Svenda
 */
public class StateModel {
    private short STATE_KEYGEN = STATE_UNINITIALIZED;
    
    // Protocol state constants
    public static final short STATE_UNINITIALIZED                       = (short) -1;
    public static final short STATE_QUORUM_CLEARED                      = (short) 0;
    public static final short STATE_QUORUM_INITIALIZED                  = (short) 1;
    public static final short STATE_KEYGEN_CLEARED                      = (short) 2;
    public static final short STATE_KEYGEN_PRIVATEGENERATED             = (short) 3;
    public static final short STATE_KEYGEN_COMMITMENTSCOLLECTED         = (short) 4;
    public static final short STATE_KEYGEN_SHARESCOLLECTED              = (short) 5;
    public static final short STATE_KEYGEN_KEYPAIRGENERATED             = (short) 6;

    
    public static final short FNC_QuorumContext_GetXi                   = (short) 0xf001;
    public static final short FNC_QuorumContext_GetYi                   = (short) 0xf002;
    public static final short FNC_QuorumContext_Invalidate              = (short) 0xf003;
    public static final short FNC_QuorumContext_GetY                    = (short) 0xf004;
    public static final short FNC_QuorumContext_GetShareCommitment      = (short) 0xf005;
    public static final short FNC_QuorumContext_SetYs                   = (short) 0xf006;
    public static final short FNC_QuorumContext_SetShareCommitment      = (short) 0xf007;
    public static final short FNC_QuorumContext_GenerateExampleBackdooredKeyPair = (short) 0xf008;
    public static final short FNC_QuorumContext_InitAndGenerateKeyPair  = (short) 0xf009;
    public static final short FNC_QuorumContext_GetState                = (short) 0xf00a;
    public static final short FNC_QuorumContext_Reset                   = (short) 0xf00b;
    public static final short FNC_QuorumContext_SetupNew                = (short) 0xf00c;
    
    
    public static final short FNC_QuorumContext_Encrypt                 = (short) 0xf010;
    public static final short FNC_QuorumContext_DecryptShare            = (short) 0xf011;
    public static final short FNC_QuorumContext_Sign_RetrieveRandomRi   = (short) 0xf012;
    public static final short FNC_QuorumContext_Sign                    = (short) 0xf013;
    public static final short FNC_QuorumContext_Sign_GetCurrentCounter  = (short) 0xf014;
    
    
    public static final short FNC_QuorumContext_VerifyCallerAuthorization = (short) 0xf011;
    
    public static final short FNC_QuorumContext_GenerateRandomData      = (short) 0xf012;
    
    
    
    
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
            case FNC_QuorumContext_SetupNew:
                if (currentState == STATE_QUORUM_CLEARED) break; 
                        
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
            case STATE_QUORUM_CLEARED:
                break; // quorum can can be cleared from any state
            case STATE_QUORUM_INITIALIZED:
                if (currentState == STATE_QUORUM_CLEARED) break; 
            case STATE_KEYGEN_CLEARED:
                break; // keypair can be cleared from any state
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
