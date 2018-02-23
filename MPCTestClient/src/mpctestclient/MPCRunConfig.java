package mpctestclient;

import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import javafx.util.Pair;
import mpc.MPCApplet;

/**
 *
 * @author Petr Svenda
 */
public class MPCRunConfig {

    public int targetReaderIndex = 0;
    public short numPlayers = 4;
    public short thisCardID = 0;
    public int numWholeTestRepeats = 1;
    public int numSingleOpRepeats = 3;
    public Class appletToSimulate;
    public short[] perfStops = null;
    public short perfStopComplete = -1;
    public ArrayList<String> failedPerfTraps = new ArrayList<>();
    public ArrayList<String> perfResultsSubparts = new ArrayList<>();
    public HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw = new HashMap<>(); // hashmap with key being perf trap id, folowed by pair <prevTrapID, elapsedTimeFromPrev>
    FileOutputStream perfFile;
    public String cardName;
    byte[] appletAID = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0a, (byte) 0x4d, (byte) 0x50, (byte) 0x43, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x74, (byte) 0x31};

    public enum CARD_TYPE {

        PHYSICAL, JCOPSIM, JCARDSIMLOCAL, JCARDSIMREMOTE
    }
    CARD_TYPE testCardType = CARD_TYPE.PHYSICAL;

    public static MPCRunConfig getDefaultConfig() {
        MPCRunConfig runCfg = new MPCRunConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.numPlayers = 4;
        runCfg.thisCardID = 0;
        runCfg.numWholeTestRepeats = 1;
        runCfg.numSingleOpRepeats = 3;
        runCfg.testCardType = CARD_TYPE.PHYSICAL;
        runCfg.appletToSimulate = MPCApplet.class;
        runCfg.cardName = "unknown";

        return runCfg;
    }
}
