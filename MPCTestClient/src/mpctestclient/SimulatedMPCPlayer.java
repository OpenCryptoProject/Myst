package mpctestclient;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

import ds.ov2.bignat.Bignat;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
class SimulatedMPCPlayer implements MPCPlayer {
    public short playerID;

    //Key Pair
    public BigInteger priv_key_BI;
    public ECPoint pub_key_EC;
    public byte[] pub_key_Hash;
    public ECPoint curve_G;
    public BigInteger curve_n;
    //Signing
    public byte[] secret_seed;//{ (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    public BigInteger k_Bn;
    public ECPoint Ri_EC;
    public byte[] Ri_Hash;

    //For preloading
    public BigInteger k_Bn_pre;
    public ECPoint Ri_EC_pre;
    public byte[] Ri_Hash_pre;

    public SimulatedMPCPlayer(short playerID, ECPoint G, BigInteger n) throws NoSuchAlgorithmException {
        this.playerID = playerID;
        curve_G = G;
        curve_n = n;

        this.KeyGen();
        SecureRandom random = new SecureRandom();
        secret_seed = new byte[32];
        random.nextBytes(secret_seed);
    }

    //
    // MPCPlayer methods
    //
    @Override
    public byte[] Gen_Rin(short quorumIndex, short i) throws NoSuchAlgorithmException, Exception {
        Bignat counter = Util.makeBignatFromValue(i);
        ECPoint Rin = curve_G.multiply(new BigInteger(PRF(counter, this.secret_seed)));
        return Rin.getEncoded(false);
    }
    
    @Override
    public ECPoint GetPubKey(short quorumIndex) {
        return pub_key_EC;
    }
    @Override
    public short GetPlayerIndex(short quorumIndex) {
        return playerID;
    }
    @Override
    public byte[] GetPubKeyHash(short quorumIndex) {
        return pub_key_Hash;
    }
    @Override
    public ECPoint GetAggregatedPubKey(short quorumIndex) {
        return null;
    }    
    @Override
    public BigInteger GetE(short quorumIndex) {
        return null; 
    }

    @Override
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerID) throws Exception {
        // TODO: at the moment, simulated player performs nothing
        return true;
    }
    @Override
    public boolean Reset(short quorumIndex) throws Exception {
        // TODO: at the moment, simulated player performs nothing
        return true;
    }
    @Override
    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext) throws Exception {
        Bignat roundBn = Util.makeBignatFromValue(round);
        return Sign(roundBn, Util.ECPointDeSerialization(Rn, 0), plaintext);
    }
    @Override
    public boolean GenKeyPair(short quorumIndex) throws Exception {
        //this.KeyGen();
        return true;
    }
    @Override
    public boolean RetrievePubKeyHash(short quorumIndex) throws Exception {
        return true;
    }
    @Override
    public boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr) throws Exception {
        // TODO: store pub key hash optionally
        return true;
    }
    @Override
    public byte[] RetrievePubKey(short quorumIndex) throws Exception {
        return pub_key_EC.getEncoded(false);
    }
    @Override
    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr) throws Exception {
        return true;
    }
    @Override
    public boolean RetrieveAggPubKey(short quorumIndex) throws Exception {
        return true;
    }
    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext) throws Exception {
        return null; // implement encryption for simulated players 
    }
    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext) throws Exception {
        ECPoint c1 = Util.ECPointDeSerialization(ciphertext, 0);
        ECPoint xc1_share = c1.multiply(priv_key_BI);
        return xc1_share.getEncoded(false);
    }
    
    
    
    //
    // SimulatedMPCPlayer helper methods
    //
    private final void SetPrivKey(BigInteger privkey) {
        priv_key_BI = privkey;
        pub_key_EC = curve_G.multiply(priv_key_BI);
    }

    private final void KeyGen() throws NoSuchAlgorithmException {
        // Keypair + hash
        SecureRandom rnd = new SecureRandom();
        priv_key_BI = new BigInteger(256, rnd);
        if (MPCTestClient._FIXED_PLAYERS_RNG) {
            System.out.println("WARNING: _FIXED_PLAYERS_RNG == true");
            // If true, don't generate random key, but use fixed one instead
            priv_key_BI = new BigInteger("B346675518084623BC111CC53FF615B152A3F6D1585278370FA1BA0EA160237E".getBytes());
        }
        pub_key_EC = curve_G.multiply(priv_key_BI);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(pub_key_EC.getEncoded(false));
        pub_key_Hash = md.digest();
    }

    private BigInteger Sign(Bignat i, ECPoint R_EC, byte[] plaintext) throws NoSuchAlgorithmException {
        //Gen e (e will be the same in all signature shares)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        //System.out.println("Simulated: Plaintext:" + client.bytesToHex(plaintext));
        //System.out.println("Simulated: Ri,n:     " + client.bytesToHex(R_EC.getEncoded(false)));
        md.update(plaintext);
        md.update(R_EC.getEncoded(false)); // R_EC is the sum of the r_i's
        byte[] e = md.digest();
        BigInteger e_BI = new BigInteger(1, e);

        //Gen s_i
        this.k_Bn = new BigInteger(PRF(i, secret_seed));

        BigInteger s_i_BI = this.k_Bn.subtract(e_BI.multiply(this.priv_key_BI));
        s_i_BI = s_i_BI.mod(curve_n);

        /* BUGBUG: I'm cheating a bit here, and use the e returned by the JC.
         Btw e is always the same, so it can actually be computed 
         on the host if this helps with optimizing the applet */
        //System.out.println("Simulated: s:        " + client.bytesToHex(s_i_BI.toByteArray()));
        //System.out.println("Simulated: e:        " + client.bytesToHex(e) + "\n");
        return s_i_BI;
    }

    private byte[] PRF(Bignat i, byte[] seed) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.reset();
        md.update(i.as_byte_array());
        md.update(seed);
        return md.digest();
    }
}
