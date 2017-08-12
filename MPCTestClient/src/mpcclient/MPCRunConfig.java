package mpcclient;

import mpc.MPCApplet;

/**
 *
 * @author Petr Svenda
 */
public class MPCRunConfig {
    int targetReaderIndex = 0;
    short numPlayers = 4;
    short thisCardID = 0;
    int numWholeTestRepeats = 1;
    int numSingleOpRepeats = 3;
    public Class appletToSimulate;    
    
    public enum CARD_TYPE {
        PHYSICAL, JCOPSIM, JCARDSIMLOCAL, JCARDSIMREMOTE
    }
    CARD_TYPE testCardType = CARD_TYPE.PHYSICAL;
    
    static MPCRunConfig getDefaultConfig() {
        MPCRunConfig runCfg = new MPCRunConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.numPlayers = 4;
        runCfg.thisCardID = 0;
        runCfg.numWholeTestRepeats = 1;
        runCfg.numSingleOpRepeats = 3;
        runCfg.testCardType = CARD_TYPE.PHYSICAL;
        runCfg.appletToSimulate = MPCApplet.class;
        
        return runCfg;
    }
}
