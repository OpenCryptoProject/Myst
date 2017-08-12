package mpc;

public class Parameters {
	// State
	public static boolean SETUP = false; // Have the scheme parameters been set?

	// MPC Parameters
	public static short NUM_PLAYERS = 0; // BUGBUG: duplication with DKG
	public static short CARD_INDEX_THIS = 0; // BUGBUG: duplication with DKG
        
        public static byte[] cardIDLong = null; // unique card ID generated during applet install
        
        public static void allocate() {
            cardIDLong = new byte[Consts.CARD_ID_LONG_LENGTH];
        }
	public static void Reset() {
		NUM_PLAYERS = 0;
		CARD_INDEX_THIS = 0;
		SETUP = false;
	}

}
