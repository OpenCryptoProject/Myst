package mpctestclient;

import java.math.BigInteger;
import java.util.ArrayList;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Petr Svenda
 */
public class MPCGlobals {
    public static ECCurve curve;
    public static BigInteger p;
    public static BigInteger a;
    public static BigInteger b;
    public static BigInteger n;
    public static ECPoint G;
    public static ECParameterSpec ecSpec;

    public static BigInteger secret = BigInteger.valueOf(0);
    public static ECPoint PubKey;
    public static ECPoint AggPubKey;
    public static ECPoint R_EC;

    public static ECPoint c1;
    public static ECPoint c2;

    static ArrayList<SimulatedPlayer> players = new ArrayList<>();

    public static ECPoint[] Rands;    
}
