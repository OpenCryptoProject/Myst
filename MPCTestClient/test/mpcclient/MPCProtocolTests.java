package mpcclient;

import mpctestclient.MPCTestClient;
import mpctestclient.MPCRunConfig;
import mpc.Consts;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;


/**
 *
 * @author Petr Svenda
 */
public class MPCProtocolTests {
    
    public MPCProtocolTests() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @AfterMethod
    public void tearDownMethod() throws Exception {
    }
    
    @Test
    void runMPCProtocol_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.targetReaderIndex = 0;
        runCfg.numPlayers = 4;
        runCfg.thisCardID = 0;
        runCfg.numWholeTestRepeats = 1;
        runCfg.numSingleOpRepeats = 3;
        
        // Execute once
        MPCTestClient.TestMPCProtocol_v20170520(runCfg);
        
        // Execute 2x
        runCfg.numWholeTestRepeats = 2;
        MPCTestClient.TestMPCProtocol_v20170520(runCfg);

        // Execute 10x
        runCfg.numWholeTestRepeats = 10;
        MPCTestClient.TestMPCProtocol_v20170520(runCfg);
    }
    
    @Test
    void runMPCProtocol_2playersOnly_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = 2;
        runCfg.numSingleOpRepeats = 1;
        // Execute once
        MPCTestClient.TestMPCProtocol_v20170520(runCfg);
    }

    @Test
    void runMPCProtocol_maxNumPlayers_realCard() throws Exception {
        MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
        runCfg.numPlayers = Consts.MAX_NUM_PLAYERS;
        // Execute once
        mpctestclient.MPCTestClient.TestMPCProtocol_v20170520(runCfg);
    }
    
    
    
}
