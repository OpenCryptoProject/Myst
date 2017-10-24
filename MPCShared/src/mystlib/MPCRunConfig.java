package mystlib;

import java.io.FileOutputStream;
import java.util.ArrayList;
import javax.smartcardio.CardChannel;

/**
 *
 * @author Petr Svenda
 */
public class MPCRunConfig {
    int targetReaderIndex = 0;
    int numPlayers = 4;
    public Class appletToSimulate;
    ArrayList<CardProfile> detectedCards;
    FileOutputStream perfFile;
    public String cardName;
    byte[] appletAID = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0a, (byte) 0x4d, (byte) 0x50, (byte) 0x43, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x74, (byte) 0x31};
    
    public enum CARD_TYPE {
        PHYSICAL, JCOPSIM, JCARDSIMLOCAL, JCARDSIMREMOTE
    }
    public CARD_TYPE testCardType = CARD_TYPE.PHYSICAL;
    
    public static MPCRunConfig getDefaultConfig() {
        MPCRunConfig runCfg = new MPCRunConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.numPlayers = 4;
        runCfg.testCardType = CARD_TYPE.PHYSICAL;
        runCfg.cardName = "unknown";
        runCfg.detectedCards = new ArrayList<>();
        return runCfg;
    }
}
