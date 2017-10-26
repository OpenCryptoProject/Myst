package mpctestclient;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.util.ArrayList;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class CardManagement {

    static Long m_lastTransmitTime = new Long(0);

    // Card Logistics
    private static CardChannel Connect(MPCRunConfig runCfg) throws Exception {
        switch (runCfg.testCardType) {
            case PHYSICAL: {
                return ConnectPhysicalCard(runCfg.targetReaderIndex, runCfg.appletAID);
            }
            case JCOPSIM: {
                return ConnectJCOPSimulator(runCfg.targetReaderIndex, runCfg.appletAID);
            }
            case JCARDSIMLOCAL: {
                return ConnectJCardSimLocalSimulator(runCfg.appletToSimulate, runCfg.appletAID);
            }
            case JCARDSIMREMOTE: {
                return null; // Not implemented yet
            }
            default:
                return null;
        }

    }

    public static void ConnectAllPhysicalCards(byte[] appletAID, ArrayList<CardChannel> cardsList) throws Exception {
        System.out.print("Looking for physical cards... ");
        connectToAllCardsByTerminalFactory(TerminalFactory.getDefault(), appletAID, cardsList);
    }

    private static void connectToAllCardsByTerminalFactory(TerminalFactory factory, byte[] appAID, ArrayList<CardChannel> cardsList) throws CardException {
        ArrayList<CardTerminal> terminals = new ArrayList<>();

        Card card = null;
        try {
            for (CardTerminal t : factory.terminals().list()) {
                terminals.add(t);
                if (t.isCardPresent()) {
                    System.out.print("Connecting...");
                    card = t.connect("*"); // Connect with the card

                    System.out.println(" Done.");

                    System.out.print("Establishing channel...");
                    CardChannel channel = card.getBasicChannel();

                    System.out.println(" Done.");

                    // Select applet (mpcapplet)
                    System.out.println("Smartcard: Selecting applet...");
                    CommandAPDU cmd = new CommandAPDU(appAID);
                    ResponseAPDU response = transmit(channel, cmd);

                    if (response.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
                        cardsList.add(channel);
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Failed.");
        }

        System.out.println("MPC cards found: " + cardsList.size());
    }

    public static CardChannel ConnectPhysicalCard(int targetReaderIndex, byte[] appletAID) throws Exception {
        System.out.print("Looking for physical cards... ");
        return connectToCardByTerminalFactory(TerminalFactory.getDefault(), targetReaderIndex, appletAID);
    }

    public static CardChannel ConnectJCOPSimulator(int targetReaderIndex, byte[] appletAID) throws Exception {
        // JCOP Simulators
        System.out.print("Looking for JCOP simulators...");
        int[] ports = new int[]{8050};
        return connectToCardByTerminalFactory(TerminalFactory.getInstance("JcopEmulator", ports), targetReaderIndex, appletAID);
    }

    public static CardChannel ConnectJCardSimLocalSimulator(Class appletClass, byte[] appAID) throws Exception {
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        CAD cad = new CAD(System.getProperties());
        JavaxSmartCardInterface simulator = (JavaxSmartCardInterface) cad.getCardInterface();
        byte[] installData = new byte[0];
        AID appletAID = new AID(appAID, (short) 0, (byte) appAID.length);

        AID appletAIDRes = simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        simulator.selectApplet(appletAID);
        return new SimulatedCardChannelLocal(simulator, appletAIDRes);
    }

    private static CardChannel connectToCardByTerminalFactory(TerminalFactory factory, int targetReaderIndex, byte[] appAID) throws CardException {
        ArrayList<CardTerminal> terminals = new ArrayList<>();

        boolean card_found = false;
        CardTerminal terminal = null;
        Card card = null;
        try {
            for (CardTerminal t : factory.terminals().list()) {
                terminals.add(t);
                if (t.isCardPresent()) {
                    card_found = true;
                }
            }
            System.out.println("Success.");
        } catch (Exception e) {
            System.out.println("Failed.");
        }

        if (card_found) {
            System.out.println("Cards found: " + terminals);

            terminal = terminals.get(targetReaderIndex); // Prioritize physical card over simulations

            System.out.print("Connecting...");
            card = terminal.connect("*"); // Connect with the card

            System.out.println(" Done.");

            System.out.print("Establishing channel...");
            CardChannel channel = card.getBasicChannel();

            System.out.println(" Done.");

            // Select applet (mpcapplet)
            System.out.println("Smartcard: Selecting applet...");

            CommandAPDU cmd = new CommandAPDU(appAID);

            ResponseAPDU response = transmit(channel, cmd);

        } else {
            System.out.print("Failed to find physical card.");
        }

        if (card != null) {
            return card.getBasicChannel();
        } else {
            return null;
        }
    }

    public static ResponseAPDU transmit(CardChannel channel, CommandAPDU cmd)
            throws CardException {
        log(cmd);

        long elapsed = -System.currentTimeMillis();
        ResponseAPDU response = channel.transmit(cmd);
        elapsed += System.currentTimeMillis();
        m_lastTransmitTime = elapsed;
        log(response, elapsed);

        return response;
    }

    private static void log(CommandAPDU cmd) {
        System.out.printf("--> %s\n", Util.toHex(cmd.getBytes()),
                cmd.getBytes().length);
    }

    private static void log(ResponseAPDU response, long time) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("<-- %s %s (%d)\n", Util.toHex(data), swStr,
                    data.length);
        } else {
            System.out.printf("<-- %s\n", swStr);
        }
        if (time > 0) {
            System.out.printf(String.format("Elapsed time %d ms\n", time));
        }
    }

    private static void log(ResponseAPDU response) {
        log(response, 0);
    }

    public static boolean checkSW(ResponseAPDU response) {
        if (response.getSW() != (ISO7816.SW_NO_ERROR & 0xffff)) {
            System.err.printf("Received error status: %02X.\n",
                    response.getSW());
            return false;
        }
        return true;
    }

}
