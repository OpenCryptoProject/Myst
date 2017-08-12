package mpc;

import javacard.framework.Util;

/**
 *
 * @author petrs
 */
public class Player {
    public byte[] hash = null;          // Hash of player's input
    public boolean bHashValid = false;  // Is hash currently valid?
    public byte[] Ys = null;            // Player's share
    public boolean bYsValid = false;    // Is player's share (Ys) currently valid?

    
    public void Copy(Player AnotherPlayer) {
    	Util.arrayCopyNonAtomic(AnotherPlayer.hash, (short) 0, this.hash, (short)0, (short) AnotherPlayer.hash.length);
    	this.bHashValid = AnotherPlayer.bHashValid;
    	Util.arrayCopyNonAtomic(AnotherPlayer.Ys, (short) 0, this.Ys, (short)0, (short) AnotherPlayer.Ys.length);
    	this.bYsValid = AnotherPlayer.bYsValid;
    }
    

}

