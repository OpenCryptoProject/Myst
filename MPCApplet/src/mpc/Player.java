package mpc;

import javacard.framework.Util;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class Player {
    public byte[] hash = null;          // Hash of player's input
    public boolean bHashValid = false;  // Is hash currently valid?
    public byte[] Ys = null;            // TODO: Player's share - can be removed as COMPUTE_Y_ONTHEFLY will be only option
    public boolean bYsValid = false;    // Is player's share (Ys) currently valid?

/* unused 20170904    
    public void Copy(Player AnotherPlayer) {
    	Util.arrayCopyNonAtomic(AnotherPlayer.hash, (short) 0, this.hash, (short)0, (short) AnotherPlayer.hash.length);
    	this.bHashValid = AnotherPlayer.bHashValid;
    	Util.arrayCopyNonAtomic(AnotherPlayer.Ys, (short) 0, this.Ys, (short)0, (short) AnotherPlayer.Ys.length);
    	this.bYsValid = AnotherPlayer.bYsValid;
    }
*/   

}

