package mysthost;

import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import javafx.util.Pair;

/**
 *
 * @author Petr Svenda
 */
public class MPCRunConfig {
    int targetReaderIndex = 0;
    short numPlayers = 4;
    short thisCardID = 0;
    public short[] perfStops = null;
    public short perfStopComplete = -1;
    public ArrayList<String> failedPerfTraps = new ArrayList<>();
    public ArrayList<String> perfResultsSubparts = new ArrayList<>();
    public HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw = new HashMap<>(); // hashmap with key being perf trap id, folowed by pair <prevTrapID, elapsedTimeFromPrev>
    FileOutputStream perfFile;
    public String cardName;

    
    public enum CARD_TYPE {
        PHYSICAL, JCOPSIM, JCARDSIMLOCAL, JCARDSIMREMOTE
    }
    CARD_TYPE testCardType = CARD_TYPE.PHYSICAL;
    
    static MPCRunConfig getDefaultConfig() {
        MPCRunConfig runCfg = new MPCRunConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.numPlayers = 4;
        runCfg.thisCardID = 0;
        runCfg.testCardType = CARD_TYPE.PHYSICAL;
        runCfg.cardName = "unknown";
        
        return runCfg;
    }
}
