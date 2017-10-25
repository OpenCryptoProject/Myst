package mpctestclient;

import ds.ov2.bignat.Bignat;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import javacard.framework.ISO7816;
import javax.smartcardio.ResponseAPDU;
import mpc.Consts;
import static mpctestclient.MPCTestClient.bytesToHex;
import static mpctestclient.MPCTestClient.mpcGlobals;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class Util {

    public static String toHex(byte[] bytes) {
        return toHex(bytes, 0, bytes.length);
    }

    public static String toHex(byte[] bytes, int offset, int len) {
        // StringBuilder buff = new StringBuilder();
        String result = "";

        for (int i = offset; i < offset + len; i++) {
            result += String.format("%02X", bytes[i]);
        }

        return result;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    
    
    /* Utils */
    public static short getShort(byte[] buffer, int offset) {
        return ByteBuffer.wrap(buffer, offset, 2).order(ByteOrder.BIG_ENDIAN).getShort();
    }

    public static short readShort(byte[] data, int offset) {
        return (short) (((data[offset] << 8)) | ((data[offset + 1] & 0xff)));
    }

    public static byte[] shortToByteArray(int s) {
        return new byte[]{(byte) ((s & 0xFF00) >> 8), (byte) (s & 0x00FF)};
    }
    
    public static int shortToByteArray(short s, byte[] array, int arrayOffset) {
        array[arrayOffset] = (byte) ((s & 0xFF00) >> 8);
        array[arrayOffset + 1] = (byte) (s & 0x00FF);
        return arrayOffset + 2;
    }
    
    
    
    public static byte[] joinArray(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        final byte[] result = new byte[length];

        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }

        return result;
    }

    public static byte[] trimLeadingZeroes(byte[] array) {
        short startOffset = 0;
        for (int i = 0; i < array.length; i++) {
            if (array[i] != 0) {
                break;
            } else {
                // still zero
                startOffset++;
            }
        }

        byte[] result = new byte[array.length - startOffset];
        System.arraycopy(array, startOffset, result, 0, array.length - startOffset);
        return result;
    }

    public static byte[] concat(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c = new byte[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

    public static byte[] concat(byte[] a, byte[] b, byte[] c) {
        byte[] tmp_conc = concat(a, b);
        return concat(tmp_conc, c);

    }
    
    public static ECPoint ECPointDeSerialization(byte[] serialized_point,
            int offset) {

        byte[] x_b = new byte[256 / 8];
        byte[] y_b = new byte[256 / 8];

		// System.out.println("Serialized Point: " + toHex(serialized_point));
		// src -- This is the source array.
        // srcPos -- This is the starting position in the source array.
        // dest -- This is the destination array.
        // destPos -- This is the starting position in the destination data.
        // length -- This is the number of array elements to be copied.
        System.arraycopy(serialized_point, offset + 1, x_b, 0, Consts.SHARE_BASIC_SIZE);
        BigInteger x = new BigInteger(bytesToHex(x_b), 16);
        // System.out.println("X:" + toHex(x_b));
        System.arraycopy(serialized_point, offset + (Consts.SHARE_BASIC_SIZE + 1), y_b, 0, Consts.SHARE_BASIC_SIZE);
        BigInteger y = new BigInteger(bytesToHex(y_b), 16);
        // System.out.println("Y:" + toHex(y_b));

        ECPoint point = mpcGlobals.curve.createPoint(x, y);

        return point;
    }

    public static ECPoint randECPoint() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        ECParameterSpec ecSpec_named = ECNamedCurveTable.getParameterSpec("secp256r1"); // NIST P-256
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecSpec_named);
        KeyPair apair = kpg.generateKeyPair();
        ECPublicKey apub = (ECPublicKey) apair.getPublic();
        return apub.getQ();
    }    
    
    public static byte[] IntToBytes(int val) {
        byte[] data = new byte[5];
        if (val < 0) {
            data[0] = 0x01;
        } else {
            data[0] = 0x00;
        }

        int unsigned = Math.abs(val);
        data[1] = (byte) (unsigned >>> 24);
        data[2] = (byte) (unsigned >>> 16);
        data[3] = (byte) (unsigned >>> 8);
        data[4] = (byte) unsigned;

        return data;
    }

    public static int BytesToInt(byte[] data) {
        int val = (data[1] << 24)
                | ((data[2] & 0xFF) << 16)
                | ((data[3] & 0xFF) << 8)
                | (data[4] & 0xFF);

        if (data[0] == 0x01) {
            val = val * -1;
        }

        return val;
    }    
    
    private static boolean checkSW(ResponseAPDU response) {
        if (response.getSW() != (ISO7816.SW_NO_ERROR & 0xffff)) {
            System.err.printf("Received error status: %02X.\n",
                    response.getSW());
            return false;
        }
        return true;
    }

    public static byte[] hexStringToByteArray(String s) {
        String sanitized = s.replace(" ", "");
        byte[] b = new byte[sanitized.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(sanitized.substring(index, index + 2), 16);
            b[i] = (byte) v;
        }
        return b;
    }

    public static Bignat makeBignatFromValue(int i) {
        Bignat bn = new Bignat((short) 4);
        setBignatValue(bn, i);
        return bn;
    }
    public static Bignat makeBignatFromValue(short i) {
        Bignat bn = new Bignat((short) 2);
        setBignatValue(bn, i);
        return bn;
    }
    private static void setBignatValue(Bignat bn, int  i) {
        //Super bad & ugly way of converting short to Bignat (I've added a proper function in the actual lib)
        Bignat one = new Bignat((short) 2);
        one.one();
        bn.zero();
        for (int j = 0; j < i; j++) {
            bn.add(one);
        }
    }
}
