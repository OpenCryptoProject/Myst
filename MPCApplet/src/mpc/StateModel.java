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
        // Check for functions which can be called from any state
        switch (requestedFnc) {
            case FNC_QuorumContext_Reset:  return;    
            case FNC_QuorumContext_GetState: return;
            case FNC_QuorumContext_Invalidate: return;    
        }
        
        // Check if function can be called from current state
        switch (currentState) {
            case STATE_QUORUM_CLEARED:
                if (requestedFnc == FNC_QuorumContext_SetupNew)  return;                   
                ISOException.throwIt(Consts.SW_FUNCTINNOTALLOWED); // if reached, function is not allowed in given state
    
            case STATE_QUORUM_INITIALIZED:
                ISOException.throwIt(Consts.SW_FUNCTINNOTALLOWED); // if reached, function is not allowed in given state
                
            case STATE_KEYGEN_CLEARED:
                if (requestedFnc == FNC_QuorumContext_InitAndGenerateKeyPair) return;
                ISOException.throwIt(Consts.SW_FUNCTINNOTALLOWED);

            case STATE_KEYGEN_PRIVATEGENERATED:
                if (requestedFnc == FNC_QuorumContext_GetShareCommitment) return;      
                if (requestedFnc == FNC_QuorumContext_SetShareCommitment) return;      
                ISOException.throwIt(Consts.SW_FUNCTINNOTALLOWED); // if reached, function is not allowed in given state

            case STATE_KEYGEN_COMMITMENTSCOLLECTED:
                if (requestedFnc == FNC_QuorumContext_SetYs) return;      
                if (requestedFnc == FNC_QuorumContext_GetYi) return;      
                ISOException.throwIt(Consts.SW_FUNCTINNOTALLOWED); // if reached, function is not allowed in given state
    
            case STATE_KEYGEN_SHARESCOLLECTED:
                ISOException.throwIt(Consts.SW_FUNCTINNOTALLOWED); // if reached, function is not allowed in given state
    
            case STATE_KEYGEN_KEYPAIRGENERATED:
                if (requestedFnc == FNC_QuorumContext_GetXi)  return;
                if (requestedFnc == FNC_QuorumContext_GetY)  return;
                if (requestedFnc == FNC_QuorumContext_Encrypt)  return;                   
                if (requestedFnc == FNC_QuorumContext_DecryptShare)  return;                   
                if (requestedFnc == FNC_QuorumContext_Sign_RetrieveRandomRi) return;                   
                if (requestedFnc == FNC_QuorumContext_Sign)  return;                   
                if (requestedFnc == FNC_QuorumContext_Sign_GetCurrentCounter)  return;                   

                ISOException.throwIt(Consts.SW_FUNCTINNOTALLOWED); // if reached, function is not allowed in given state

            default:
                ISOException.throwIt(Consts.SW_UNKNOWNSTATE);
       }
    }

    
    private static short MakeStateTransition(short currentState, short newState) {
        // Check for functions which can be reached from any state
        switch (newState) {
            case STATE_QUORUM_CLEARED: 
                return newState;
        }

        // Check if transition from currentState -> newState is allowed
        switch (currentState) {
            case STATE_QUORUM_CLEARED:
                if (newState == STATE_QUORUM_INITIALIZED) return newState;
                 ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION); // if reached, transition is not allowed
            case STATE_QUORUM_INITIALIZED:
                if (newState == STATE_KEYGEN_CLEARED) return newState;
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION); // if reached, transition is not allowed
            case STATE_KEYGEN_CLEARED:
                if (newState == STATE_KEYGEN_PRIVATEGENERATED) return newState;        
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION); // if reached, transition is not allowed
            case STATE_KEYGEN_PRIVATEGENERATED:
                if (newState == STATE_KEYGEN_COMMITMENTSCOLLECTED) return newState;
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
            case STATE_KEYGEN_COMMITMENTSCOLLECTED:
                if (newState == STATE_KEYGEN_SHARESCOLLECTED) return newState;
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
            case STATE_KEYGEN_SHARESCOLLECTED:
                if (newState == STATE_KEYGEN_KEYPAIRGENERATED) return newState;
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
            case STATE_KEYGEN_KEYPAIRGENERATED:
                ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
            default:
                ISOException.throwIt(Consts.SW_UNKNOWNSTATE);
        }        
        ISOException.throwIt(Consts.SW_INCORRECTSTATETRANSITION);
        return newState;
    } 
}
