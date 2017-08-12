package mpcclient;

import static mpcclient.MPCTestClient.G;

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
class SimulatedPlayer {
    public short playerID;
    
    //Key Pair
    public BigInteger priv_key_BI;
    public ECPoint pub_key_EC;
    public byte[] pub_key_Hash;
    
    //Signing
    public byte[] secret_seed = new byte[32];//{ (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    public BigInteger k_Bn;
    public ECPoint Ri_EC;
    public byte[] Ri_Hash;
    
    
    //For preloading
    public BigInteger k_Bn_pre;
    public ECPoint Ri_EC_pre;
    public byte[] Ri_Hash_pre;
    

    public SimulatedPlayer(short playerID) throws NoSuchAlgorithmException{
        this.playerID = playerID;
        this.KeyGen();
        SecureRandom random = new SecureRandom();
        byte[] secret_seed = new byte[32];
        random.nextBytes(secret_seed);
        
    }
    
   public final void SetPrivKey(BigInteger privkey) {
	   priv_key_BI = privkey;
	   pub_key_EC = G.multiply(priv_key_BI);
   }
   
   public final void KeyGen() throws NoSuchAlgorithmException{
       // Keypair + hash
       SecureRandom rnd = new SecureRandom();
       priv_key_BI = new BigInteger(256, rnd);
       //priv_key_BI = new BigInteger("B346675518084623BC111CC53FF615B152A3F6D1585278370FA1BA0EA160237E".getBytes());
       pub_key_EC = G.multiply(priv_key_BI);
       MessageDigest md = MessageDigest.getInstance("SHA-256");
       md.update(pub_key_EC.getEncoded(false));
       pub_key_Hash = md.digest();
   }

   
   /*
   public void Gen_Ri() throws NoSuchAlgorithmException{
	   // Temp r for signing + hash
	   SecureRandom rnd = new SecureRandom();
       k_Bn = new BigInteger(256, rnd);
       Ri_EC = G.multiply(k_Bn);
       MessageDigest md = MessageDigest.getInstance("SHA-256");
       md.reset();
       md.update(Ri_EC.getEncoded(false));
       Ri_Hash = md.digest();
       
       //For preloading
       k_Bn_pre = new BigInteger(256, rnd);
       Ri_EC_pre = G.multiply(k_Bn_pre);
       md.reset();
       md.update(Ri_EC_pre.getEncoded(false));
       Ri_Hash_pre = md.digest();
   }*/
   
   /*
   public void Gen_next_Ri() throws NoSuchAlgorithmException{
	   //Previously preloaded pair is now the current one
	   k_Bn = k_Bn_pre;
	   Ri_EC = Ri_EC_pre;
	   Ri_Hash = Ri_Hash_pre;
       
       //For preloading
	   SecureRandom rnd = new SecureRandom();
       k_Bn_pre = new BigInteger(256, rnd);
       Ri_EC_pre = G.multiply(k_Bn_pre);
       MessageDigest md = MessageDigest.getInstance("SHA-256");
       md.reset();
       md.update(Ri_EC_pre.getEncoded(false));
       Ri_Hash_pre = md.digest();
   }
   */
   
   
        
   public BigInteger Sign(Bignat i, ECPoint R_EC, byte[] plaintext) throws NoSuchAlgorithmException{
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
        s_i_BI = s_i_BI.mod(MPCTestClient.n);

        /*I'm cheating a bit here, and use the e returned by the JC.
        Btw e is always the same, so it can actually be computed 
        on the host if this helps with optimizing the applet */
        
        //System.out.println("Simulated: s:        " + client.bytesToHex(s_i_BI.toByteArray()));
        //System.out.println("Simulated: e:        " + client.bytesToHex(e) + "\n");
        
        return s_i_BI;
   }

   
   public byte[] Gen_Rin(Bignat i) throws NoSuchAlgorithmException{
	   ECPoint Rin = G.multiply(new BigInteger(PRF(i, this.secret_seed)));
	   return Rin.getEncoded(false);
   }
   
   
   public byte[] Gen_Rin(Bignat i, byte[] seed) throws NoSuchAlgorithmException {
	   ECPoint Rin = G.multiply(new BigInteger(PRF(i, seed)));
	   return Rin.getEncoded(false);
   }
   
   
   public byte[] PRF(Bignat i, byte[] seed) throws NoSuchAlgorithmException {
	   MessageDigest md = MessageDigest.getInstance("SHA-256");
	   md.reset();
	   md.update(i.as_byte_array());
	   md.update(seed);
	   return md.digest();
   }
   
   
}
