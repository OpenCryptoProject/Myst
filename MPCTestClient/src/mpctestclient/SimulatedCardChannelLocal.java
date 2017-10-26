package mpctestclient;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.nio.ByteBuffer;
import javacard.framework.AID;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Petr Svenda
 */
public class SimulatedCardChannelLocal extends CardChannel {

    JavaxSmartCardInterface m_simulator;
    SimulatedCard m_card;
    AID m_appletAID;

    SimulatedCardChannelLocal(JavaxSmartCardInterface simulator, AID appletAIDRes) {
        m_simulator = simulator;
        m_card = new SimulatedCard();
        m_appletAID = appletAIDRes;
    }

    @Override
    public Card getCard() {
        return m_card;
    }

    @Override
    public int getChannelNumber() {
        return 0;
    }

    @Override
    public ResponseAPDU transmit(CommandAPDU apdu) throws CardException {
        ResponseAPDU responseAPDU = null;

        try {
            responseAPDU = this.m_simulator.transmitCommand(apdu);
            // Add delay corresponding to real cards
            //int delay = OperationTimes.getCardOperationDelay(apdu);
            //Thread.sleep(delay);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return responseAPDU;
    }

    @Override
    public int transmit(ByteBuffer bb, ByteBuffer bb1) throws CardException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void close() throws CardException {
        m_simulator.reset();
        m_simulator.deleteApplet(m_appletAID);
    }
}
