package mpc;


import javacard.security.MessageDigest;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class MPCCryptoOperations {
    RandomData randomData = null;
    MessageDigest md = null;
    
    Bignat temp_sign_counter = null; 

    ECPointBase placeholder = null; 
    ECPointBase c2_EC = null;   
    ECPointBase GenPoint = null;
    ECPointBase plaintext_EC = null;
    ECPointBase tmp_EC = null;
    byte[] y_Bn = null;
    byte[] encResult = null;
    byte[] e_arr = null;
    byte[] tmp_k_n = null;
    byte[] prf_result = null;

    Bignat modulo_Bn = null;
    Bignat e_Bn = null;
    Bignat s_Bn = null;
    Bignat xe_Bn = null;
    Bignat xi_Bn = null;
    Bignat aBn = null;
    
    Bignat resBn1 = null;
    Bignat resBn2 = null;
    Bignat resBn3 = null;
    
    // AddPoint operations
    Bignat four_Bn = null;
    Bignat five_Bn = null;
    Bignat p_Bn = null;
    
    byte[] m_shortByteArray = null; // used to return short represenated as array of 2 bytes
    byte[] tmp_arr = null; // TODO: used as  array for temporary result -> move to resource manager

    
    static final short SHIFT_BYTES_AAPROX = Consts.SHARE_DOUBLE_SIZE_CARRY;
    static short res2Len = (short) ((short) 97 - SHIFT_BYTES_AAPROX);

    //static byte[] citConst = {(byte) 0x01, (byte) 0x00, (byte) 0x01};
    //static byte[] citConst = {(byte) 0x0, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xbc, (byte) 0xe6, (byte) 0xfa, (byte) 0xad, (byte) 0xa7, (byte) 0x17, (byte) 0x9e, (byte) 0x84, (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2, (byte) 0xfc, (byte) 0x63, (byte) 0x25, (byte) 0x51};
    static byte[] r_for_BigInteger = {
        (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, 
        (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe, (byte) 0xff, (byte) 0xff, (byte) 0xff, 
        (byte) 0xff, (byte) 0x43, (byte) 0x19, (byte) 0x05, (byte) 0x52, (byte) 0xdf, (byte) 0x1a, (byte) 0x6c, 
        (byte) 0x21, (byte) 0x01, (byte) 0x2f, (byte) 0xfd, (byte) 0x85, (byte) 0xee, (byte) 0xdf, (byte) 0x9b, 
        (byte) 0xfe, (byte) 0x67};

    static byte[] aBn_pow_2 = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, 
        (byte) 0xFF, (byte) 0xFD, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC, (byte) 0x86, (byte) 0x32, 
        (byte) 0x0A, (byte) 0xA4, (byte) 0x44, (byte) 0x66, (byte) 0xE2, (byte) 0xE8, (byte) 0xC0, (byte) 0x94, 
        (byte) 0xD3, (byte) 0x4F, (byte) 0x59, (byte) 0xED, (byte) 0x28, (byte) 0x63, (byte) 0x78, (byte) 0xEE, 
        (byte) 0x70, (byte) 0x50, (byte) 0x78, (byte) 0x7E, (byte) 0xEB, (byte) 0xFF, (byte) 0x3C, (byte) 0x87, 
        (byte) 0xC1, (byte) 0x57, (byte) 0x3A, (byte) 0x89, (byte) 0xD7, (byte) 0x29, (byte) 0x38, (byte) 0x99, 
        (byte) 0xDB, (byte) 0x3F, (byte) 0x42, (byte) 0x81, (byte) 0x40, (byte) 0x09, (byte) 0xDF, (byte) 0xC9, 
        (byte) 0x49, (byte) 0x4B, (byte) 0x31, (byte) 0xC9, (byte) 0x7F, (byte) 0x8A, (byte) 0x8D, (byte) 0x71};

    static byte[] modulo_Bn_pow_2 = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x02, 
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, 
        (byte) 0x79, (byte) 0xCD, (byte) 0xF5, (byte) 0x5B, (byte) 0xD4, (byte) 0x61, (byte) 0x47, (byte) 0xAE, 
        (byte) 0x13, (byte) 0x12, (byte) 0x4D, (byte) 0xD7, (byte) 0x5F, (byte) 0x81, (byte) 0xF2, (byte) 0x26, 
        (byte) 0x00, (byte) 0x43, (byte) 0x66, (byte) 0x1F, (byte) 0x1D, (byte) 0x81, (byte) 0x9D, (byte) 0x01, 
        (byte) 0x9A, (byte) 0x02, (byte) 0xFC, (byte) 0xD8, (byte) 0x5D, (byte) 0x72, (byte) 0x4A, (byte) 0xA1, 
        (byte) 0x32, (byte) 0xAD, (byte) 0x5E, (byte) 0x5D, (byte) 0xE4, (byte) 0x69, (byte) 0xC2, (byte) 0x7B, 
        (byte) 0xAB, (byte) 0x0D, (byte) 0xBA, (byte) 0xA1, (byte) 0x5A, (byte) 0x16, (byte) 0x83, (byte) 0xA1};
    
    public MPCCryptoOperations(ECConfig eccfg) {
        temp_sign_counter = new Bignat((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        tmp_arr = JCSystem.makeTransientByteArray(Consts.SHARE_DOUBLE_SIZE_CARRY, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);

        placeholder = ECPointBuilder.createPoint(SecP256r1.KEY_LENGTH);
        placeholder.initializeECPoint_SecP256r1();

        c2_EC = ECPointBuilder.createPoint(SecP256r1.KEY_LENGTH);
        c2_EC.initializeECPoint_SecP256r1();

        GenPoint = ECPointBuilder.createPoint(SecP256r1.KEY_LENGTH);
        GenPoint.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);

        plaintext_EC = ECPointBuilder.createPoint(SecP256r1.KEY_LENGTH);
        plaintext_EC.initializeECPoint_SecP256r1();

        tmp_EC = ECPointBuilder.createPoint(SecP256r1.KEY_LENGTH);
        tmp_EC.initializeECPoint_SecP256r1();
        
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        
        y_Bn = JCSystem.makeTransientByteArray(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        
        encResult = JCSystem.makeTransientByteArray(Consts.SHARE_DOUBLE_SIZE_CARRY, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        
        e_arr = JCSystem.makeTransientByteArray(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        
        tmp_k_n = JCSystem.makeTransientByteArray(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        prf_result = JCSystem.makeTransientByteArray(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        
        modulo_Bn = new Bignat(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) 0, SecP256r1.r, (short) 0);
        
        aBn = new mpc.Bignat(Consts.SHARE_DOUBLE_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        
        aBn.set_from_byte_array((short) (aBn.length() - (short) r_for_BigInteger.length), r_for_BigInteger, (short) 0, (short) r_for_BigInteger.length);
        
        e_Bn = new Bignat(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        s_Bn = new Bignat(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        xi_Bn = new Bignat(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        xe_Bn = new Bignat(Consts.SHARE_DOUBLE_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        
        resBn1 = new Bignat((short) ((short) (eccfg.bnh.MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8) + 1), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        resBn2 = new Bignat(Consts.SHARE_BASIC_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        resBn3 = new Bignat(Consts.SHARE_DOUBLE_SIZE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        
        // AddPoint objects
        four_Bn = new Bignat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        five_Bn = new Bignat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        p_Bn = new Bignat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, eccfg.bnh);
        
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        
        m_shortByteArray = JCSystem.makeTransientByteArray((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
    }
    
    public short Encrypt(QuorumContext quorumCtx, byte[] plaintext_arr, short plaintext_arr_offset, byte[] outArray, short perfStop) {
        short outOffset = (short) 0;

        if (perfStop == (short) 1) {ISOException.throwIt((short) (Consts.PERF_ENCRYPT + perfStop));}

        // Encrypt
        randomData.generateData(y_Bn, (short) 0, (short) y_Bn.length); //4ms
        
        if (perfStop == (short) 2) {ISOException.throwIt((short) (Consts.PERF_ENCRYPT + perfStop));}

        // Preset KeyAgreement - we will use it twice so set it only once and reuse // 60ms
        if (ECPointBase.ECMultiplHelper != null) { // Use prepared engine - cards with native support for EC
            ECPointBase.disposable_priv.setS(y_Bn, (short) 0, (short) y_Bn.length);
            ECPointBase.ECMultiplHelper.init(ECPointBase.disposable_priv); // Set multiplier        
        }

        if (perfStop == (short) 3) {ISOException.throwIt((short) (Consts.PERF_ENCRYPT + perfStop));}
        
        // Gen c2 first as we will reuse same output array
        // c2 = m + (xG) + (yG) = y(xG) + m = yPub + m
        //ECPointBase.ScalarMultiplication(CryptoObjects.KeyPair.GetY(), ECPointBase.ECMultiplHelper, c2_EC); // y(xG) //170ms
        if (ECPointBase.ECMultiplHelper != null) { 
            // Use prepared engine - cards with native support for EC
            c2_EC.ScalarMultiplication(quorumCtx.GetY(), ECPointBase.ECMultiplHelper, c2_EC); // y(xG) //170ms
        }
        else {
            // Use this with JCMathLib
            c2_EC.ScalarMultiplication(quorumCtx.GetY(), y_Bn, c2_EC); // y(xG)
        }
        
        if (perfStop == (short) 4) {ISOException.throwIt((short) (Consts.PERF_ENCRYPT + perfStop));}

        ECPointBase.ECPointAddition(c2_EC, plaintext_arr, plaintext_arr_offset, c2_EC); // +m //150ms
        
        if (perfStop == (short) 5) {ISOException.throwIt((short) (Consts.PERF_ENCRYPT + perfStop));}

        // Gen c1 now 
        if (ECPointBase.ECMultiplHelper != null) {
            // Use prepared engine - cards with native support for EC
            outOffset += placeholder.ScalarMultiplication(GenPoint, ECPointBase.ECMultiplHelper, outArray); // yG // 129ms 
        }
        else {
            // Use this with JCMathLib
            outOffset += placeholder.ScalarMultiplication(GenPoint, y_Bn, outArray); // yG 
        }
        if (perfStop == (short) 6) {ISOException.throwIt((short) (Consts.PERF_ENCRYPT + perfStop));}

        outOffset += c2_EC.getW(outArray, outOffset); // append c2_EC behind yG

        return outOffset;
    }

    // Share is -x_ic1
    public short DecryptShare(QuorumContext quorumCtx, byte[] c1_c2_arr, short c1_c2_arr_offset, byte[] outputArray, short perfStop) {

        if (perfStop == (short) 1) {ISOException.throwIt((short) (Consts.PERF_DECRYPT + perfStop));}   
        if (perfStop == (short) 2) {ISOException.throwIt((short) (Consts.PERF_DECRYPT + perfStop));}            

        short len;
        if (ECPointBase.ECMultiplHelperDecrypt != null) {
            // Use prepared engine - cards with native support for EC
            /* is already set from Reset method
             byte[] point = CryptoObjects.KeyPair.Getxi();
             EC_Utils.disposable_privDecrypt.setS(point, (short) 0, (short) point.length);
             EC_Utils.ECMultiplHelperDecrypt.init(EC_Utils.disposable_privDecrypt); // Set multiplier
             */
            len = placeholder.ScalarMultiplication(c1_c2_arr, c1_c2_arr_offset, Consts.SHARE_DOUBLE_SIZE_CARRY, ECPointBase.ECMultiplHelperDecrypt, outputArray); // -xyG
        } else {
            // Use this with JCMathLib
            len = placeholder.ScalarMultiplication(c1_c2_arr, c1_c2_arr_offset, Consts.SHARE_DOUBLE_SIZE_CARRY, quorumCtx.GetXi(), outputArray); // -xyG
        }        

        if (perfStop == (short) 3) {ISOException.throwIt((short) (Consts.PERF_DECRYPT + perfStop));}

        return len; 
    }

    static short sendBignat(Bignat value, byte[] outputArray, short outputBaseOffset) {
        short outOffset = outputBaseOffset;
        Util.arrayCopyNonAtomic(value.as_byte_array(), (short) 0, outputArray, outOffset, (short) value.as_byte_array().length);
        outOffset += (short) value.as_byte_array().length;
        return (short) (outOffset - outputBaseOffset);        
    }
    
    /*
    public final static byte[] xe_Bn_testInput1 = {
     (byte) 0x03, (byte) 0xBD, (byte) 0x28, (byte) 0x6B, (byte) 0x6A, (byte) 0x22, (byte) 0x1F, (byte) 0x1B,
     (byte) 0xFC, (byte) 0x08, (byte) 0xC6, (byte) 0xC5, (byte) 0xB0, (byte) 0x3F, (byte) 0x0B, (byte) 0xEA,
     (byte) 0x6C, (byte) 0x38, (byte) 0xBE, (byte) 0xBA, (byte) 0xCF, (byte) 0x20, (byte) 0x2A, (byte) 0xAA,
     (byte) 0xDF, (byte) 0xAC, (byte) 0xA3, (byte) 0x70, (byte) 0x38, (byte) 0x32, (byte) 0xF8, (byte) 0xCC,
     (byte) 0xE0, (byte) 0xA8, (byte) 0x70, (byte) 0x88, (byte) 0xE9, (byte) 0x17, (byte) 0x21, (byte) 0xA3,
     (byte) 0x4C, (byte) 0x8D, (byte) 0x0B, (byte) 0x97, (byte) 0x11, (byte) 0x98, (byte) 0x02, (byte) 0x46,
     (byte) 0x04, (byte) 0x56, (byte) 0x40, (byte) 0xA1, (byte) 0xAE, (byte) 0x34, (byte) 0xC1, (byte) 0xFB,
     (byte) 0x7D, (byte) 0xB8, (byte) 0x45, (byte) 0x28, (byte) 0xC6, (byte) 0x1B, (byte) 0xC6, (byte) 0xD0};
    */

    public short Sign(QuorumContext quorumCtx, Bignat i, byte[] Rn_plaintext_arr, short plaintextOffset, short plaintextLength, byte[] outputArray, short outputBaseOffset, short perfStop) {
        
        if (perfStop == (short) 1) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} //153ms
        // 1. Check counter
        if (!MPCApplet.bIsSimulator) {
            if (quorumCtx.signature_counter.lesser(i)==false) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
        }

        if (perfStop == (short) 2) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));}  //+8ms     
    	// 2. Compute e = H(M||R_n)
        md.reset();
        md.update(Rn_plaintext_arr, plaintextOffset, Consts.SHARE_DOUBLE_SIZE_CARRY); // Hash plaintext
        md.doFinal(Rn_plaintext_arr, (short) (plaintextOffset+Consts.SHARE_DOUBLE_SIZE_CARRY), Consts.SHARE_DOUBLE_SIZE_CARRY, e_arr, (short) 0); //Hash R_n
	e_Bn.from_byte_array(Consts.SHARE_BASIC_SIZE, (short) 0, e_arr, (short) 0);

		


        if (perfStop == (short) 3) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} // +15ms
        // s
        //s_Bn.zero();
        s_Bn.from_byte_array(Consts.SHARE_BASIC_SIZE, (short) 0, PRF(i, quorumCtx.signature_secret_seed), (short) 0); // s


        if (perfStop == (short) 4) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} // +36ms
        // xe
        //xe_Bn.zero();
        xe_Bn.resize_to_max(true); // xe_Bn is shrinked below => resize long-term object back to initial maximum size 

        if (perfStop == (short) 5) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} // +18ms
        //xi_Bn.zero();
        xi_Bn.from_byte_array(Consts.SHARE_BASIC_SIZE, (short) 0, quorumCtx.GetXi(), (short) 0);
        //xe_Bn.mult(xi_Bn, e_Bn);  // 330ms
        xe_Bn.mult_RSATrick(xi_Bn, e_Bn); // 90ms
        //test_multRSATrick(xi_Bn, e_Bn, null, xe_Bn);

        if (perfStop == (short) 6) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} // +111ms
        // Compute xe_Bn mod modulo_Bn 
        
        // -- begin - original working command
        //xe_Bn.remainder_divide(modulo_Bn, null); // 470ms
        // -- end -

/*        
        short outOffset = outputBaseOffset;
        Util.arrayCopyNonAtomic(xe_Bn.as_byte_array(), (short) 0, outputArray, outOffset, (short) xe_Bn.as_byte_array().length);
        outOffset += (short) xe_Bn.as_byte_array().length;
*/
/*        
        // -- begin - Trick via shifted RSA: ((n<<k)^1 mod (r << k) ) >> k;    k == 256b == 32B
        // Problem doesn't work as n << k is longer than shifted modulus (r << k)
        // Shift n<<k
        Util.arrayFillNonAtomic(Bignat.fastResizeArray, (short) 0, (short) Bignat.fastResizeArray.length, (byte) 0);
        // fastResizeArray.length must be at least xe_Bn.size + k (in bytes)
        // asser(xe_Bn.size == (short) (Bignat.MOD_RSA_LENGTH / 8))
        Util.arrayCopyNonAtomic(xe_Bn.as_byte_array(), (short) 0, Bignat.fastResizeArray, (short) 0, xe_Bn.size()); 
        // Prepare output array which will contain mod result after shift (=> first 32B are zeroes)
        Util.arrayFillNonAtomic(xe_Bn.as_byte_array(), (short) 0, Consts.SHARE_SIZE_32, (byte) 0);
        // mod_cipher is already initialized with proper key with shifted r << k
        // Store result in already shifted position
        Bignat.mod_cipher.doFinal(Bignat.fastResizeArray, (short) 0, (short) (Bignat.MOD_RSA_LENGTH / 8), Bignat.fastResizeArray, (short) 0);
        // Store result back to xe_Bn on already shifted position
        Util.arrayCopyNonAtomic(Bignat.fastResizeArray, (short) 0, xe_Bn.as_byte_array(), (short) 0, e_Bn.size());
        //ISOException.throwIt((short) 0x666);
*/        
/*         
        Util.arrayCopyNonAtomic(xe_Bn.as_byte_array(), (short) 0, outputArray, outOffset, (short) xe_Bn.as_byte_array().length);
        outOffset += (short) xe_Bn.as_byte_array().length;
        return (short) (outOffset - outputBaseOffset);
*/
        // -- end - Trick via shifted RSA
        
        //xe_Bn.multRSATrick(xe_Bn, cit); xe_Bn.shiftBytes_right((short) 36); // modulo_Bn approximated by 4294967297 / 2^288
        //xe_Bn.multRSATrick(xe_Bn, cit); xe_Bn.shiftBytes_right((short) 61); // modulo_Bn approximated by 115792089210356248762697446949407573529996955224135760342422259061068512044369 / 2^488
        //xe_Bn.shiftBytes_right((short) 32); // modulo_Bn approximated by 1/2^256
        
        // -- begin - trick with RSA multiplication X/2^k

        // BUGBUG: set test input
        //xe_Bn.from_byte_array((short) xe_Bn_testInput1.length, (short) 0, xe_Bn_testInput1, (short) 0);

        // xe_Bn % aBn = xe_Bn - ((xe_Bn * aBn) >> k) * aBn
        // (xe_Bn * aBn)
        //resBn1.mult(aBn, xe_Bn);
        //resBn1.multRSATrick(aBn, xe_Bn);
        resBn1.mult_rsa_trick(aBn, xe_Bn, aBn_pow_2, null); // as aBn is fixed, aBn^2 can be precomputed
        //resBn1.mult_rsa_trick(aBn, xe_Bn, null, null); // BUGBUG: just for testing, return back option with aBn_pow_2
        //test_multRSATrick(aBn, xe_Bn, null,resBn1);
        
        // ((n * a) >> k)
        // ((n * a) >> k) * r
        //resBn1.shiftBytes_right(SHIFT_BYTES_AAPROX); // 520 == 65*8
        //resBn2.from_byte_array(resBn2.size(), (short) 0, resBn1.as_byte_array(), (short) (resBn1.size() - resBn2.size()));
        resBn2.set_from_byte_array((short) 0, resBn1.as_byte_array(), (short) ((short) (resBn1.length() - SHIFT_BYTES_AAPROX) - resBn2.length()), resBn2.length());
                
        //resBn3.mult(modulo_Bn, resBn2);
        //resBn3.multRSATrick(modulo_Bn, resBn2);
        resBn3.mult_rsa_trick(modulo_Bn, resBn2, modulo_Bn_pow_2, null); // as modulo_Bn is fixed, modulo_Bn^2 can be precomputed
        //resBn3.mult_rsa_trick(modulo_Bn, resBn2, null, null); // BUGBUG: just for testing, return back option with modulo_Bn_pow_2
        //test_multRSATrick(modulo_Bn, resBn2, null, resBn3);


        // n - ((n * a) >> k) * r
        byte[] result = xe_Bn.as_byte_array();
        byte[] inter = resBn3.as_byte_array();
        Bignat.subtract(result, (short) 0, (short) result.length, inter, (short) 0, (short) inter.length);
        
        //return sendBignat(xe_Bn, outputArray, outputBaseOffset);
        //ISOException.throwIt((short) 0x666);
        // -- end - trick with RSA multiplication X/2^k
        

        if (perfStop == (short) 7) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} // +276ms  
        xe_Bn.shrink(); // Resize back to 32 Bytes

        if (perfStop == (short) 8) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} // +19ms

        if (s_Bn.lesser(xe_Bn)) {  // remember s holds only k at this point
            s_Bn.add(modulo_Bn);
        }
        else {
            // bogus branch to prevent direct leak if s_Bn.lesser(xe_Bn) info in timing channel
            resBn2.add(modulo_Bn);
        }

        if (perfStop == (short) 9) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} // +22ms

        // s = k -xe
        s_Bn.times_minus(xe_Bn, (short) 0, (short) 1); // k-xe

        if (perfStop == (short) 10) {ISOException.throwIt((short) (Consts.PERF_SIGN + perfStop));} //+9ms
        

        //if (perfStop == (short) 11) {ISOException.throwIt((short) (PERF_SIGN + perfStop));}
	quorumCtx.signature_counter.copy(i);
		
        // Return result
        short outOffset = outputBaseOffset;
        Util.arrayCopyNonAtomic(s_Bn.as_byte_array(), (short) 0, outputArray, outOffset, (short) s_Bn.as_byte_array().length);
        outOffset += (short) s_Bn.as_byte_array().length;
        Util.arrayCopyNonAtomic(e_Bn.as_byte_array(), (short) 0, outputArray, (short) s_Bn.as_byte_array().length, (short) e_Bn.as_byte_array().length);
        outOffset += (short) e_Bn.as_byte_array().length;
        return (short) (outOffset - outputBaseOffset);
        
    }
    
    
    public short addPoint(byte[] points_array, short points_array_offset, short Length, byte[] outputArray, short outputBaseOffset, short perfStop) {
    	
    	/*
    	//Coordinates
    	Bignat x_P_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
    	Bignat y_P_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
    	Bignat x_Q_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
    	Bignat y_Q_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
    	*/
    	
    	//Helper Objects
    	//ECPoint TmpPoint = ECPointBuilder.buildECPoint(ECPointBuilder.TYPE_EC_FP_POINT, (short) SecP256r1.KEY_LENGTH);
        //EC_Utils.initializeECPoint (TmpPoint);
    	
    	//Bignat one_Bn = new Bignat((short)64, false);
    	//one_Bn.one();
    	//one_Bn.athousand();
    	//one_Bn.from_byte_array((short) 32, (short) 0, SecP256r1.p, (short) 0);
    	
    	//Bignat four_Bn = new Bignat((short)32, false);
    	four_Bn.four();
    	//four_Bn.from_byte_array((short) 32, (short) 32, SecP256r1.p, (short) 0);
    	//Bignat five_Bn = new Bignat((short)32, false);
    	five_Bn.five();
    	
        //byte[] res_RSA = new byte[(short)64];
       
        /*
    	EC_Utils.p_Bn.from_byte_array((short) SecP256r1.p.length, (short) 0, SecP256r1.p, (short) 0);
    	//byte [] uncompressed_arr = JCSystem.makeTransientByteArray(Consts.SHARE_SIZE_CARRY_65, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
    	
    	
    	//Load Coordinates
    	x_P_Bn.from_byte_array(Consts.SHARE_SIZE_32, (short) 0, points_array, (short) (0));
    	y_P_Bn.from_byte_array(Consts.SHARE_SIZE_32, (short) 0, points_array, (short) (33));
    	x_Q_Bn.from_byte_array(Consts.SHARE_SIZE_32, (short) 0, points_array, (short) (0+65));
    	y_Q_Bn.from_byte_array(Consts.SHARE_SIZE_32, (short) 0, points_array, (short) (33+65));    	
    	
    	
    	//Bignat tmp_x_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
    	//Bignat tmp_y_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
    	Bignat l_Bn = new Bignat(Consts.SHARE_SIZE_32, false);  
    	
    	
    	    	
    	//if Points are not Coincident
    	if ((x_P_Bn.same_value(x_Q_Bn)==false) || (y_P_Bn.same_value(y_Q_Bn)==false)) {
    		//l = (y_q-y_p)/(x_q-x_p))
    		//x_r = l^2 - x_p -x_q
	    	//y_r = l(x_p-x_r)-y_p
    		
    		//A. y_q-y_p
    		if (y_Q_Bn.lesser(y_P_Bn) == true) { // y<p
    			y_Q_Bn.add(EC_Utils.p_Bn);
    		}
    		y_Q_Bn.times_minus(y_P_Bn, (short) 0, (short) 1);
    		
    		//B. x_q-x_p
    		if (x_Q_Bn.lesser(x_P_Bn) == true) { // y<p
    			x_Q_Bn.add(EC_Utils.p_Bn);
    		}
    		x_Q_Bn.times_minus(x_P_Bn, (short) 0, (short) 1);
    		
    		//C. A/B
		*/
        
        // RSA keypair data
    	//Bignat p_Bn =  new Bignat((short)32, false);
    	p_Bn.from_byte_array((short) SecP256r1.p.length, (short) 0, SecP256r1.p, (short) 0);


    	//byte[] p_64 = new byte[(short)64]; 
    	//Util.arrayFillNonAtomic(p_64, (short) 0, (short) p_64.length, (byte) 0);
    	//Util.arrayCopyNonAtomic(SecP256r1.p, (short) 0, p_64, (short)32, (short) SecP256r1.p.length);
    	
    	five_Bn.mod_exp(four_Bn, p_Bn);
                  	
    	Util.arrayCopyNonAtomic(five_Bn.as_byte_array(), (short) 0, outputArray, (short)0, (short) five_Bn.as_byte_array().length);
        return (short)five_Bn.as_byte_array().length;
    	//return (short)0;
    }    
    
    public short Gen_R_i(byte[] i, byte[] secret_arr, byte[] output_arr) {
        //PRF(i, secret_arr); is giving correct intermediate result as real card
        //short lenW = GenPoint.getW(ECPointBase.TempBuffer65, (short) 0); // Read base point into buffer
        //return placeholder.ScalarMultiplication(ECPointBase.TempBuffer65, (short) 0, lenW, PRF(i, secret_arr), output_arr); // yG 
        return placeholder.ScalarMultiplication(GenPoint, PRF(i, secret_arr), output_arr); // yG 
    }


    public byte[] PRF(short i, byte[] secret_arr) {
        return PRF(shortToByteArray(i), secret_arr);
    }
    
    public byte[] PRF(Bignat i, byte[] secret_arr) {
        return PRF(i.as_byte_array(), secret_arr);
    }
   
    public byte[] PRF(byte[] i, byte[] secret_arr) {
        //Util.arrayFillNonAtomic(prf_result, (short) 0, (short) prf_result.length, (byte) 0); // use when MessageDigest is shorter than SHARE_SIZE_32
        md.reset();
        md.update(i, (short) 0, (short) i.length);
        md.doFinal(secret_arr, (short) 0, (short) secret_arr.length, prf_result, (short) 0);
        return prf_result;
    }
    
    public byte[] shortToByteArray(short s) {
        Util.setShort(m_shortByteArray, (short) 0, s);
        return m_shortByteArray;
    }
    
    public boolean VerifyPair(byte[] Ys, short YsOffset, short YsLength, byte[] hash) {
        md.reset();
        md.doFinal(Ys, YsOffset, YsLength, tmp_arr, (short) 0);
        if (Util.arrayCompare(tmp_arr, (short) 0, hash,
                (short) 0, Consts.SHARE_BASIC_SIZE) != 0) {
            return false;
        } else {
            return true;
        }
    }
    
    
}
