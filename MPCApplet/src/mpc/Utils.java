package mpc;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class Utils {
        static byte[] m_shortByteArray = null; // used to return short represenated as array of 2 bytes
        public static void allocate() {
            m_shortByteArray = JCSystem.makeTransientByteArray((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        }
	public static byte[] shortToByteArray(short s) {
            Util.setShort(m_shortByteArray, (short) 0, s);
            return m_shortByteArray;
	}
}
