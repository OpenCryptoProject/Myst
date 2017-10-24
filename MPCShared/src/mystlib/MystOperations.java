package mystlib;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import javacard.framework.ISO7816;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Petr Svenda
 */
public class MystOperations {
    public enum CryptoOps {
        KEYGEN,
        SIGN,
        DECRYPT
    }
    public void Execute(MPCRunConfig runCfg, String inputFile, String outputFile, CryptoOps cryptoOps) throws Exception {
        // Connect to all available readers and scan for MPC applets
        ArrayList<CardChannel> cardsList = new ArrayList<>();
        CardManagement.ConnectAllPhysicalCards(runCfg.appletAID, cardsList);
        // Create card contexts, fill cards IDs
        for (CardChannel channel : cardsList) {
            CardProfile cardProfile = new CardProfile();
            cardProfile.channel = channel;
            runCfg.detectedCards.add(cardProfile);
        }
        
        // Run selected operation and store results
        switch (cryptoOps) {
            case KEYGEN: {
                break;
            }
            default: {
                System.out.println("ERROR: Unknown operation.");
            }
        }
        
        // TODO: Cleanup
    }
    
    void ScanAvailableCards(MPCRunConfig runCfg) {
        int numMPCCards = 0;
        
        //CardChannel channel = Connect(runCfg);
        System.out.println(" Done.");


        //GetCardInfo(channel);

        
        runCfg.numPlayers = numMPCCards; // Number of detected cards
    }

    private static boolean GetCardInfo(CardChannel channel, CardProfile cardProfile) throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_PERSONALIZE_GETCARDINFO, 0, 0);
        ResponseAPDU response = CardManagement.transmit(channel, cmd);

        // Parse response 
        if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
            int offset = 0;
            byte[] data = response.getData();
            System.out.println("---CARD STATE -------");
            assert (data[offset] == Consts.TLV_TYPE_CARDUNIQUEDID);
            offset++;
            short len = Util.getShort(data, offset);
            offset += 2;
            System.out.println(String.format("CardIDLong:\t\t\t %s", Util.toHex(data, offset, len)));
            offset += len;

            assert (data[offset] == Consts.TLV_TYPE_KEYPAIR_STATE);
            offset++;
            assert (Util.getShort(data, offset) == 2);
            offset += 2;
            System.out.println(String.format("KeyPair state:\t\t\t %d", Util.getShort(data, offset)));
            offset += 2;
            assert (data[offset] == Consts.TLV_TYPE_EPHIMERAL_STATE);
            offset++;
            assert (Util.getShort(data, offset) == 2);
            offset += 2;
            System.out.println(String.format("EphiKey state:\t\t\t %d", Util.getShort(data, offset)));
            offset += 2;

            assert (data[offset] == Consts.TLV_TYPE_MEMORY);
            offset++;
            assert (Util.getShort(data, offset) == 6);
            offset += 2;
            System.out.println(String.format("MEMORY_PERSISTENT:\t\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("MEMORY_TRANSIENT_RESET:\t\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("MEMORY_TRANSIENT_DESELECT:\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_COMPILEFLAGS);
            offset++;
            assert (Util.getShort(data, offset) == 4);
            offset += 2;
            System.out.println(String.format("Consts.MAX_N_PLAYERS:\t\t %d", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("DKG.PLAYERS_IN_RAM:\t\t %b", (data[offset] == 0) ? false : true));
            offset++;
            System.out.println(String.format("DKG.COMPUTE_Y_ONTHEFLY:\t\t %b ", (data[offset] == 0) ? false : true));
            offset++;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_GITCOMMIT);
            offset++;
            len = Util.getShort(data, offset);
            assert (len == 4);
            offset += 2;
            System.out.println(String.format("Git commit tag:\t\t\t 0x%s", Util.toHex(data, offset, len)));
            offset += len;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_EXAMPLEBACKDOOR);
            offset++;
            len = Util.getShort(data, offset);
            assert (len == 1);
            offset += 2;
            if (data[offset] == (byte) 0) {
                System.out.println("Applet is in normal (non-backdoored) state");
            } else {
                System.out.println("WARNING: Applet is in example 'backdoored' state with fixed private key");
            }
            offset += len;

            System.out.println("-----------------");
        }

        return CardManagement.checkSW(response);
    }
    
}
