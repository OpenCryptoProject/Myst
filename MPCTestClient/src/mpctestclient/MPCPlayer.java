package mpctestclient;

import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Petr Svenda
 */
public interface MPCPlayer {

    public BigInteger GetE(short quorumIndex);

    public byte[] Gen_Rin(short quorumIndex, short i) throws NoSuchAlgorithmException, Exception;

    public ECPoint GetPubKey(short quorumIndex);

    public ECPoint GetAggregatedPubKey(short quorumIndex);

    public short GetPlayerIndex(short quorumIndex);

    public byte[] GetPubKeyHash(short quorumIndex);

    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex) throws Exception;

    public boolean Reset(short quorumIndex) throws Exception;

    public BigInteger Sign(short quorumIndex, int round, byte[] Rn, byte[] plaintext) throws Exception;

    public boolean GenKeyPair(short quorumIndex) throws Exception;

    public boolean RetrievePubKeyHash(short quorumIndex) throws Exception;

    public boolean StorePubKeyHash(short quorumIndex, short playerIndex, byte[] hash_arr) throws Exception;

    public byte[] RetrievePubKey(short quorumIndex) throws Exception;

    public boolean StorePubKey(short quorumIndex, short playerIndex, byte[] pub_arr) throws Exception;

    public boolean RetrieveAggPubKey(short quorumIndex) throws Exception;

    public byte[] Encrypt(short quorumIndex, byte[] plaintext) throws Exception;

    public byte[] Decrypt(short quorumIndex, byte[] ciphertext) throws Exception;

    public void disconnect();
}
