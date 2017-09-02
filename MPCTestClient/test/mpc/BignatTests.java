package mpc;

import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;


/**
 *
 * @author Petr Svenda
 */
public class BignatTests {
    
    // Our constant r is 0xffffffff0000000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    public final static byte[] xe_Bn_testInput1 = {(byte) 0x03, (byte) 0xBD, (byte) 0x28, (byte) 0x6B, (byte) 0x6A, (byte) 0x22, (byte) 0x1F,
        (byte) 0x1B, (byte) 0xFC, (byte) 0x08, (byte) 0xC6, (byte) 0xC5, (byte) 0xB0, (byte) 0x3F, (byte) 0x0B, (byte) 0xEA, (byte) 0x6C,
        (byte) 0x38, (byte) 0xBE, (byte) 0xBA, (byte) 0xCF, (byte) 0x20, (byte) 0x2A, (byte) 0xAA, (byte) 0xDF, (byte) 0xAC, (byte) 0xA3,
        (byte) 0x70, (byte) 0x38, (byte) 0x32, (byte) 0xF8, (byte) 0xCC, (byte) 0xE0, (byte) 0xA8, (byte) 0x70, (byte) 0x88, (byte) 0xE9,
        (byte) 0x17, (byte) 0x21, (byte) 0xA3, (byte) 0x4C, (byte) 0x8D, (byte) 0x0B, (byte) 0x97, (byte) 0x11, (byte) 0x98, (byte) 0x02,
        (byte) 0x46, (byte) 0x04, (byte) 0x56, (byte) 0x40, (byte) 0xA1, (byte) 0xAE, (byte) 0x34, (byte) 0xC1, (byte) 0xFB, (byte) 0x7D,
        (byte) 0xB8, (byte) 0x45, (byte) 0x28, (byte) 0xC6, (byte) 0x1B, (byte) 0xC6, (byte) 0xD0};
    // xe_Bn_testInput1 % r expected output = A63C40BA30E305C0E710DE90B9FCFA67771508E48E7703BB72BD3071B80EB42F
    public final static byte[] xe_Bn_testOutput1 = {(byte) 0xA6, (byte) 0x3C, (byte) 0x40, (byte) 0xBA, (byte) 0x30, (byte) 0xE3, (byte) 0x05,
        (byte) 0xC0, (byte) 0xE7, (byte) 0x10, (byte) 0xDE, (byte) 0x90, (byte) 0xB9, (byte) 0xFC, (byte) 0xFA, (byte) 0x67, (byte) 0x77,
        (byte) 0x15, (byte) 0x08, (byte) 0xE4, (byte) 0x8E, (byte) 0x77, (byte) 0x03, (byte) 0xBB, (byte) 0x72, (byte) 0xBD, (byte) 0x30,
        (byte) 0x71, (byte) 0xB8, (byte) 0x0E, (byte) 0xB4, (byte) 0x2F};

    public final static byte[] xe_Bn_testInput2 = {(byte) 0x72, (byte) 0x44, (byte) 0x21, (byte) 0x42, (byte) 0xe9, (byte) 0xe8, (byte) 0xa7,
        (byte) 0x32, (byte) 0x26, (byte) 0xe6, (byte) 0xf9, (byte) 0xb6, (byte) 0xfb, (byte) 0xe5, (byte) 0x09, (byte) 0x2e, (byte) 0x44,
        (byte) 0xf4, (byte) 0xdd, (byte) 0x9d, (byte) 0x95, (byte) 0x6d, (byte) 0xe9, (byte) 0xa3, (byte) 0xbe, (byte) 0x25, (byte) 0x61,
        (byte) 0x00, (byte) 0x1b, (byte) 0xaf, (byte) 0x04, (byte) 0x84, (byte) 0x55, (byte) 0xcf, (byte) 0xd3, (byte) 0x33, (byte) 0x84,
        (byte) 0xbc, (byte) 0xdd, (byte) 0x6b, (byte) 0x0a, (byte) 0x20, (byte) 0x75, (byte) 0x21, (byte) 0xc3, (byte) 0x11, (byte) 0x62,
        (byte) 0x4b, (byte) 0x84, (byte) 0xfd, (byte) 0x21, (byte) 0xa1, (byte) 0xfe, (byte) 0xcb, (byte) 0x53, (byte) 0xdb, (byte) 0x15,
        (byte) 0x51, (byte) 0xf1, (byte) 0xa1, (byte) 0xa8, (byte) 0x83, (byte) 0x90, (byte) 0x6c};
    // xe_Bn_testInput2 % r expected output = 4C38E7231B781FFFCA11555D137A6F8510C761A761252958531657B612E91718
    public final static byte[] xe_Bn_testOutput2 = {(byte) 0x4C, (byte) 0x38, (byte) 0xE7, (byte) 0x23, (byte) 0x1B, (byte) 0x78, (byte) 0x1F,
        (byte) 0xFF, (byte) 0xCA, (byte) 0x11, (byte) 0x55, (byte) 0x5D, (byte) 0x13, (byte) 0x7A, (byte) 0x6F, (byte) 0x85, (byte) 0x10,
        (byte) 0xC7, (byte) 0x61, (byte) 0xA7, (byte) 0x61, (byte) 0x25, (byte) 0x29, (byte) 0x58, (byte) 0x53, (byte) 0x16, (byte) 0x57,
        (byte) 0xB6, (byte) 0x12, (byte) 0xE9, (byte) 0x17, (byte) 0x18};
    
    // 2^256 % r where r = 0xffffffff0000000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    public final static byte[] const2kmodR = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x43, (byte) 0x19, (byte) 0x05, (byte) 0x52, (byte) 0x58, (byte) 0xe8, (byte) 0x61,
        (byte) 0x7b, (byte) 0x0c, (byte) 0x46, (byte) 0x35, (byte) 0x3d, (byte) 0x03, (byte) 0x9c, (byte) 0xda, (byte) 0xaf};
    
    public BignatTests() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @AfterMethod
    public void tearDownMethod() throws Exception {
    }
    
/*    
    static byte[] testNonOptimizedModuloBignat(byte[] n, byte[] r) {
        Bignat modulo_Bn = new Bignat((short) Consts.RND_SIZE, false);
        modulo_Bn.from_byte_array((short) r.length, (short) (0), r, (short) 0);
        Bignat xe_Bn = new Bignat(Consts.SHARE_SIZE_64, false);
        xe_Bn.from_byte_array((short) n.length, (short) (0), n, (short) 0);
        xe_Bn.remainder_divide(modulo_Bn, null);
        byte[] result = xe_Bn.as_byte_array();
        // Trim leading zeroes from result array 
        result = mpcclient.MPCTestClient.trimLeadingZeroes(result);

        return result;
    }
            
    @Test
    void testNonOptimizedModuloBignat() {
        System.out.format("\n*********** BEGIN: Modulo non-optimized with Bignat  ********\n");
        byte[] result = testNonOptimizedModuloBignat(xe_Bn_testInput1, SecP256r1.r);
        Assert.assertEquals(result, xe_Bn_testOutput1);
        System.out.format("testInput1 mod r = %s\n", mpcclient.MPCTestClient.bytesToHex(result));
        result = testNonOptimizedModuloBignat(xe_Bn_testInput2, SecP256r1.r);
        Assert.assertEquals(result, xe_Bn_testOutput2);
        System.out.format("testInput2 mod r = %s\n", mpcclient.MPCTestClient.bytesToHex(result));

        System.out.format("*********** END: Modulo non-optimized with Bignat  ********\n");
    }
*/
    @Test
    void anotherTest() {
        assert(false);
    }
/*    
    static byte[] testOptimizedModuloBignat2(byte[] n, byte[] r) {
        Bignat modulo_Bn = new Bignat((short) Consts.RND_SIZE, false);
        modulo_Bn.from_byte_array((short) r.length, (short) (0), r, (short) 0);

        Bignat n0 = new Bignat(Consts.SHARE_SIZE_64, false);
        Bignat n1 = new Bignat(Consts.SHARE_SIZE_32, false);
        Bignat const2kmodR_Bn = new Bignat(Consts.SHARE_SIZE_32, false);

        const2kmodR_Bn.set_from_byte_array((short) 0, const2kmodR, (short) 0, (short) const2kmodR.length);
        n1.set_from_byte_array((short) 0, xe_Bn_testInput1, (short) 0, (short) ((short) xe_Bn_testInput1.length / 2));
        n0.set_from_byte_array((short) ((short) xe_Bn_testInput1.length / 2), xe_Bn_testInput1, (short) ((short) xe_Bn_testInput1.length / 2), (short) ((short) xe_Bn_testInput1.length / 2));
        Bignat resBn = new Bignat(Consts.SHARE_SIZE_64, false);

        // a1 x (2^k mod r) + a0 
        resBn.mult(n1, const2kmodR_Bn);

        if (Bignat.add(resBn.as_byte_array(), (short) 0, resBn.size(), n0.as_byte_array(), (short) 0, n0.size())) {
            // Carry occured
            resBn.as_byte_array()[(short) 0] = 0x01;
        }

        System.out.format("a1 x (2^k mod r) + a0  = %s\n", client.client.bytesToHex(resBn.as_byte_array()));

        return client.client.trimLeadingZeroes(resBn.as_byte_array());
    }    
    
    static byte[] testModuloBigInteger(byte[] n, byte[] r) {
        // Non-Optimized modulo with Java's BigInteger     
        BigInteger a2 = new BigInteger(1, n);
        BigInteger r2 = new BigInteger(1, r);
        a2.negate();
        BigInteger res2 = a2.mod(r2);
        System.out.format("a2 mod r2 = %s\n", res2.toString(16));
        // Non-Optimized modulo with Java's BigInteger     

        // Optimized but with Java's BigInteger        
        System.out.format("\n*********** BEGIN: Modulo trick with BigInteger ********\n");
        // n % r = n - ((n * a) >> k) * r
        BigInteger testIn1 = new BigInteger(1, n);
        // Important: approx_a == mpc.SecP256r1.r but with one additional integer coding the sign
        BigInteger a3 = new BigInteger(1, const2kmodR);
        //BigInteger r3 = new BigInteger(1, mpc.SecP256r1.r);

        //(n * a)
        BigInteger res3 = a3.multiply(testIn1);
        System.out.format("n * a = %s\n", res3.toString(16));
        // ((n * a) >> k)
        res3 = res3.shiftRight(520);
        System.out.format("((n * a) >> k) = %s\n", res3.toString(16));
        // ((n * a) >> k) * r
        BigInteger res4 = res3.multiply(r2);
        System.out.format("r = %s\n", r2.toString(16));
        System.out.format("((n * a) >> k) * r = %s\n", res4.toString(16));
        // n - ((n * a) >> k) * r
        BigInteger res5 = testIn1.subtract(res4);
        System.out.format("n - ((n * a) >> k) * r = %s\n", res5.toString(16));
        System.out.format("*********** END: Modulo trick with BigInteger ********\n");
        // Optimized but with Java's BigInteger     
        
        return client.client.trimLeadingZeroes(res5.toByteArray());        
    }    
    
    @Test
    void testOptimizedModuloBignat2() {
        System.out.format("\n*********** BEGIN: Modulo trick with Bignat  ********\n");
        
        byte[] resultBigInteger = testModuloBigInteger(xe_Bn_testInput2, SecP256r1.r);
        Assert.assertEquals(resultBigInteger, xe_Bn_testOutput1);
        System.out.format("testInput2 mod r = %s\n", client.client.bytesToHex(resultBigInteger));

        byte[] result = testOptimizedModuloBignat2(xe_Bn_testInput1, SecP256r1.r);
        Assert.assertEquals(result, xe_Bn_testOutput1);
        System.out.format("testInput1 mod r = %s\n", client.client.bytesToHex(result));

        System.out.format("*********** END: Modulo trick with Bignat  ********\n");
    }
*/    
}
