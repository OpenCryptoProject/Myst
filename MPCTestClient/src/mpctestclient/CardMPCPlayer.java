package mpctestclient;

import ds.ov2.bignat.Bignat;
import ds.ov2.bignat.Convenience;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import mpc.Consts;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Petr Svenda
 */
public class CardMPCPlayer implements MPCPlayer {
    public short playerID;
    CardChannel channel = null;
    short quorumIndex = 0;
    String logFormat = "%-40s:%s%n\n-------------------------------------------------------------------------------\n";
    Long lastTransmitTime;
    boolean bFailOnAssert = true;
    HashMap<Short, Short> quorumCardIndexMap;
    BigInteger card_e_BI;
    public byte[] pub_key_Hash;
    ECPoint pubKey;
    ECPoint AggPubKey;

    CardMPCPlayer(CardChannel channel, short quorumIndex, String logFormat, Long lastTransmitTime, boolean bFailOnAssert) {
        this.channel = channel;
        this.quorumIndex = quorumIndex;
        this.logFormat = logFormat;
        this.lastTransmitTime = lastTransmitTime;
        this.bFailOnAssert = bFailOnAssert;
        this.quorumCardIndexMap = new HashMap<>();
    }
    
    //
    // MPCPlayer methods
    //
    @Override
    public short GetPlayerID() {
        return playerID;
    }

    @Override
    public byte[] GetPubKeyHash() {
        return pub_key_Hash;
    }    
    @Override
    public BigInteger GetE() {
        return card_e_BI;
    }
    @Override
    public ECPoint GetPubKey() {
        return null;
    }
    
    
    @Override
    public byte[] Gen_Rin(short i) throws NoSuchAlgorithmException, Exception {
        byte[] rin = RetrieveRI(channel, quorumIndex, i);
        System.out.format(logFormat, "Retrieve Ri,n (INS_SIGN_RETRIEVE_RI):", Util.bytesToHex(rin));
        return rin;
    }

    //
    // CardMPCPlayer public methods
    //
    public void SetBackdoorExample(CardChannel channel, boolean bMakeBackdoored)
            throws Exception {

        CommandAPDU cmd;
        if (bMakeBackdoored) {
            // If to be backdoored, set p1 to 0x55
            cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SET_BACKDOORED_EXAMPLE, 0x55, 0x00, 0x00);
        } else {
            cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SET_BACKDOORED_EXAMPLE, 0x00, 0x00, 0x00);
        }
        ResponseAPDU response = transmit(channel, cmd);
    }
    
    public boolean GetCardInfo() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_PERSONALIZE_GETCARDINFO, 0, 0);
        ResponseAPDU response = transmit(channel, cmd);

        // Parse response 
        if (response.getSW() == (Consts.SW_SUCCESS & 0xffff)) {
            int offset = 0;
            byte[] data = response.getData();
            System.out.println("---CARD STATE -------");
            assert (data[offset] == Consts.TLV_TYPE_CARDUNIQUEDID);
            offset++;
            short len = Util.getShort(data, offset);
            offset += 2;
            System.out.println(String.format("CardIDLong:\t\t\t %s", Util.toHex(data, offset, len)));
            offset += len;

            assert (data[offset] == Consts.TLV_TYPE_KEYPAIR_STATE);
            offset++;
            assert (Util.getShort(data, offset) == 2);
            offset += 2;
            System.out.println(String.format("KeyPair state:\t\t\t %d", Util.getShort(data, offset)));
            offset += 2;
            assert (data[offset] == Consts.TLV_TYPE_EPHIMERAL_STATE);
            offset++;
            assert (Util.getShort(data, offset) == 2);
            offset += 2;
            System.out.println(String.format("EphiKey state:\t\t\t %d", Util.getShort(data, offset)));
            offset += 2;

            assert (data[offset] == Consts.TLV_TYPE_MEMORY);
            offset++;
            assert (Util.getShort(data, offset) == 6);
            offset += 2;
            System.out.println(String.format("MEMORY_PERSISTENT:\t\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("MEMORY_TRANSIENT_RESET:\t\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("MEMORY_TRANSIENT_DESELECT:\t %d bytes", Util.getShort(data, offset)));
            offset += 2;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_COMPILEFLAGS);
            offset++;
            assert (Util.getShort(data, offset) == 4);
            offset += 2;
            System.out.println(String.format("Consts.MAX_N_PLAYERS:\t\t %d", Util.getShort(data, offset)));
            offset += 2;
            System.out.println(String.format("DKG.PLAYERS_IN_RAM:\t\t %b", (data[offset] == 0) ? false : true));
            offset++;
            System.out.println(String.format("DKG.COMPUTE_Y_ONTHEFLY:\t\t %b ", (data[offset] == 0) ? false : true));
            offset++;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_GITCOMMIT);
            offset++;
            len = Util.getShort(data, offset);
            assert (len == 4);
            offset += 2;
            System.out.println(String.format("Git commit tag:\t\t\t 0x%s", Util.toHex(data, offset, len)));
            offset += len;
            System.out.println("-----------------");

            assert (data[offset] == Consts.TLV_TYPE_EXAMPLEBACKDOOR);
            offset++;
            len = Util.getShort(data, offset);
            assert (len == 1);
            offset += 2;
            if (data[offset] == (byte) 0) {
                System.out.println("Applet is in normal (non-backdoored) state");
            } else {
                System.out.println("WARNING: Applet is in example 'backdoored' state with fixed private key");
            }
            offset += len;
            System.out.println("-----------------");
        }

        return checkSW(response);
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    private byte[] RetrieveRI(CardChannel channel, short quorumIndex, short i) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_SIGN_RETRIEVE_RI, quorumIndex, (short) i);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN_RETRIEVE_RI,
                0x00, 0x00, packetData);
        ResponseAPDU response = transmit(channel, cmd);

		//We do nothing with the key, as we just use the Aggregated R in the test cases
        // return checkSW(response);
        return response.getData();
    }    
    
    private ResponseAPDU transmit(CardChannel channel, CommandAPDU cmd)
            throws CardException {
        log(cmd);

        long elapsed = -System.currentTimeMillis();
        ResponseAPDU response = channel.transmit(cmd);
        elapsed += System.currentTimeMillis();
        lastTransmitTime = elapsed;
        log(response, elapsed);

        return response;
    }

    private void log(CommandAPDU cmd) {
        System.out.printf("--> %s\n", Util.toHex(cmd.getBytes()),
                cmd.getBytes().length);
    }

    private void log(ResponseAPDU response, long time) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("<-- %s %s (%d)\n", Util.toHex(data), swStr,
                    data.length);
        } else {
            System.out.printf("<-- %s\n", swStr);
        }
        if (time > 0) {
            System.out.printf(String.format("Elapsed time %d ms\n", time));
        }
    }

    private void log(ResponseAPDU response) {
        log(response, 0);
    }    
    


    byte[] preparePacketData(byte operationCode, short param1) {
        return preparePacketData(operationCode, 1, param1, null, null);
    }

    byte[] preparePacketData(byte operationCode, short param1, short param2) {
        return preparePacketData(operationCode, 2, param1, param2, null);
    }

    byte[] preparePacketData(byte operationCode, short param1, short param2, short param3) {
        return preparePacketData(operationCode, 3, param1, param2, param3);
    }

    static byte[] preparePacketData(byte operationCode, int numShortParams, Short param1, Short param2, Short param3) {
        int offset = 0;
        byte[] cmd = new byte[1 + 2 + 1 + 2 + numShortParams * 2];
        cmd[offset] = Consts.TLV_TYPE_MPCINPUTPACKET;
        offset++;
        Util.shortToByteArray((short) (cmd.length - 3), cmd, offset);
        offset += 2;
        cmd[offset] = operationCode;
        offset++;
        Util.shortToByteArray((short) (2 * 2), cmd, offset);
        offset += 2;
        if (numShortParams >= 1) {
            offset = Util.shortToByteArray(param1, cmd, offset);
        }
        if (numShortParams >= 2) {
            offset = Util.shortToByteArray(param2, cmd, offset);
        }
        if (numShortParams >= 3) {
            offset = Util.shortToByteArray(param3, cmd, offset);
        }

        return cmd;
    }
    /* Instructions */

    @Override
    public boolean Setup(short quorumIndex, short numPlayers, short thisPlayerIndex) throws Exception {
        quorumCardIndexMap.put(quorumIndex, thisPlayerIndex);

        byte[] packetData = preparePacketData(Consts.INS_QUORUM_SETUP_NEW, quorumIndex, numPlayers, thisPlayerIndex);

        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_QUORUM_SETUP_NEW, 0,
                0, packetData);
        ResponseAPDU response = transmit(channel, cmd);

        return checkSW(response);
    }

    @Override
    public boolean Reset(short quorumIndex) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_QUORUM_RESET, quorumIndex);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_QUORUM_RESET, 0x00, 0x00, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean GenKeyPair(short quorumIndex) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_INIT, quorumIndex);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_KEYGEN_INIT, 0x00,
                0x00, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean RetrievePubKeyHash(short quorumIndex) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_COMMITMENT, quorumIndex);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_KEYGEN_RETRIEVE_COMMITMENT,
                0x00, 0x00, packetData);
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean StorePubKeyHash(short quorumIndex, short id,
            byte[] hash_arr) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_STORE_COMMITMENT, quorumIndex, id, (short) hash_arr.length);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_KEYGEN_STORE_COMMITMENT,
                0x00, 0x00, Util.concat(packetData, hash_arr));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    @Override
    public boolean StorePubKey(short quorumIndex, short id,
            byte[] pub_arr) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_STORE_PUBKEY, quorumIndex, id, (short) pub_arr.length);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_KEYGEN_STORE_PUBKEY,
                0x00, 0x00, Util.concat(packetData, pub_arr));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }
/*
    private boolean RetrievePrivKey_DebugOnly(CardChannel channel)
            throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC,
                Consts.BUGBUG_INS_KEYGEN_RETRIEVE_PRIVKEY, 0x0, 0x0);
        ResponseAPDU response = transmit(channel, cmd);

        // Store Secret
        Bignat tmp_BN = new Bignat(Consts.SHARE_BASIC_SIZE, false);
        tmp_BN.from_byte_array(Consts.SHARE_BASIC_SIZE, (short) 0, (response.getData()),
                (short) 0);
        mpcGlobals.secret = Convenience.bi_from_bn(tmp_BN);

        return checkSW(response);
    }
*/    
    @Override
    public byte[] RetrievePubKey(short quorumIndex) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_PUBKEY, quorumIndex);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC,
                Consts.INS_KEYGEN_RETRIEVE_PUBKEY, 0x00, 0x00, packetData);
        ResponseAPDU response = transmit(channel, cmd);

        pubKey = Util.ECPointDeSerialization(response.getData(), 0);  // Store Pub

        return response.getData();
    }

    @Override
    public boolean RetrieveAggPubKey(short quorumIndex)
            throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, quorumIndex);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC,
                Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, 0x00, 0x00, packetData);
        ResponseAPDU response = transmit(channel, cmd);

        AggPubKey = Util.ECPointDeSerialization(response.getData(), 0); // Store aggregated pub

        return checkSW(response);
    }


    @Override
    public byte[] Encrypt(short quorumIndex, byte[] plaintext)
            throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_ENCRYPT, quorumIndex, (short) plaintext.length);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ENCRYPT, 0x0, 0x0, Util.concat(packetData, plaintext));
        ResponseAPDU response = transmit(channel, cmd);
        return response.getData();
    }
/*    
    private byte[] Encrypt(CardChannel channel, short quorumIndex, byte[] plaintext, MPCRunConfig runCfg, boolean bProfilePerf)
            throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_ENCRYPT, quorumIndex, (short) plaintext.length);
        if (!bProfilePerf) {
            CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ENCRYPT, 0x0, 0x0, Util.concat(packetData, plaintext));
            ResponseAPDU response = transmit(channel, cmd);
            return response.getData();
        } else {
            transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

            short[] PERFSTOPS_Encrypt = {PM.TRAP_CRYPTOPS_ENCRYPT_1, PM.TRAP_CRYPTOPS_ENCRYPT_2, PM.TRAP_CRYPTOPS_ENCRYPT_3, PM.TRAP_CRYPTOPS_ENCRYPT_4, PM.TRAP_CRYPTOPS_ENCRYPT_5, PM.TRAP_CRYPTOPS_ENCRYPT_6, PM.TRAP_CRYPTOPS_ENCRYPT_COMPLETE};
            runCfg.perfStops = PERFSTOPS_Encrypt;
            runCfg.perfStopComplete = PM.TRAP_CRYPTOPS_ENCRYPT_COMPLETE;
            long avgOpTime = 0;
            String opName = "Encrypt: ";
            for (int repeat = 0; repeat < runCfg.numSingleOpRepeats; repeat++) {
                CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ENCRYPT, 0x0, 0x0, Util.concat(packetData, plaintext));
                avgOpTime += PerfAnalyzeCommand(opName, cmd, channel, runCfg);
            }
            System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numSingleOpRepeats));
            transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

            return Encrypt(channel, quorumIndex, plaintext, runCfg, false);
        }
    }    
*/  
    @Override
    public byte[] Decrypt(short quorumIndex, byte[] ciphertext) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_DECRYPT, quorumIndex, (short) ciphertext.length);
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_DECRYPT, 0x0, 0x0, Util.concat(packetData, ciphertext));
        ResponseAPDU response = transmit(channel, cmd);

        return response.getData();
    }
    
/*    

    private byte[] Decrypt(CardChannel channel, short quorumIndex, byte[] ciphertext, MPCRunConfig runCfg, boolean bProfilePerf)
            throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_DECRYPT, quorumIndex, (short) ciphertext.length);
        if (!bProfilePerf) {
            CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_DECRYPT, 0x0, 0x0, Util.concat(packetData, ciphertext));
            ResponseAPDU response = transmit(channel, cmd);

            return response.getData();
        } else {
            transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

            short[] PERFSTOPS_Decrypt = {PM.TRAP_CRYPTOPS_DECRYPTSHARE_1, PM.TRAP_CRYPTOPS_DECRYPTSHARE_2, PM.TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE};
            runCfg.perfStops = PERFSTOPS_Decrypt;
            runCfg.perfStopComplete = PM.TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE;
            long avgOpTime = 0;
            String opName = "Decrypt: ";
            for (int repeat = 0; repeat < runCfg.numSingleOpRepeats; repeat++) {
                CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_DECRYPT, 0x0, 0x0, Util.concat(packetData, ciphertext));
                avgOpTime += PerfAnalyzeCommand(opName, cmd, channel, runCfg);
            }
            System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numSingleOpRepeats));
            transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

            return Decrypt(channel, quorumIndex, ciphertext, runCfg, false);
        }
    }
*/    

    @Override
    public BigInteger Sign(short quorumIndex, int round, byte[] plaintext, byte[] Rn) throws Exception {

        //String operationName = String.format("Signature(%s) (INS_SIGN)", msgToSign.toString());            
        byte[] signature = Sign_plain(quorumIndex, round, plaintext, Rn);

        //Parse s from Card
        Bignat card_s_Bn = new Bignat((short) 32, false);
        card_s_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 0);
        BigInteger card_s_bi = new BigInteger(1, card_s_Bn.as_byte_array());

        //Parse e from Card
        Bignat card_e_Bn = new Bignat((short) 32, false);
        card_e_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 32);
        card_e_BI = new BigInteger(1, card_e_Bn.as_byte_array());

        //System.out.println("REALCARD : s:        " + bytesToHex(card_s_Bn.as_byte_array()));
        //System.out.println("REALCARD : e:        " + bytesToHex(card_e_Bn.as_byte_array()) + "\n");
        
        return card_s_bi;
    }
    private byte[] Sign_plain(short quorumIndex, int round, byte[] plaintext, byte[] Rn) throws Exception {
        byte[] packetData = preparePacketData(Consts.INS_SIGN, quorumIndex, (short) round, (short) ((short) plaintext.length + (short) Rn.length));
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, 0x0, Util.concat(packetData, Util.concat(plaintext, Rn)));
        ResponseAPDU response = transmit(channel, cmd);

        return response.getData();
    }

    /*
     public byte[] Sign_profilePerf(short quorumIndex, int round, byte[] plaintext, byte[] Rn, MPCRunConfig runCfg, boolean bProfilePerf) throws Exception {
         // Repeated measurements if required
         long elapsed = -System.currentTimeMillis();
         int repeats = 100000;
         for (int i = 1; i < repeats; i++) {
         plaintext[5] = (byte) (i % 256);
         CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, 0x0, concat(plaintext, Rn));
         ResponseAPDU response = transmit(channel, cmd);
         }
         elapsed += System.currentTimeMillis();
         System.out.format("Elapsed: %d ms, time per Sign = %f ms\n", elapsed, elapsed / (float) repeats);

        byte[] packetData = preparePacketData(Consts.INS_SIGN, quorumIndex, (short) round, (short) ((short) plaintext.length + (short) Rn.length));
        if (!bProfilePerf) {
            CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, 0x0, Util.concat(packetData, Util.concat(plaintext, Rn)));
            ResponseAPDU response = transmit(channel, cmd);

            return response.getData();
        } else {
            // Repeated measurements if required
            transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

            short[] PERFSTOPS_Decrypt = {PM.TRAP_CRYPTOPS_SIGN_1, PM.TRAP_CRYPTOPS_SIGN_2, PM.TRAP_CRYPTOPS_SIGN_3, PM.TRAP_CRYPTOPS_SIGN_4, PM.TRAP_CRYPTOPS_SIGN_5, PM.TRAP_CRYPTOPS_SIGN_6, PM.TRAP_CRYPTOPS_SIGN_7, PM.TRAP_CRYPTOPS_SIGN_8, PM.TRAP_CRYPTOPS_SIGN_9, PM.TRAP_CRYPTOPS_SIGN_10, PM.TRAP_CRYPTOPS_SIGN_COMPLETE};
            runCfg.perfStops = PERFSTOPS_Decrypt;
            runCfg.perfStopComplete = PM.TRAP_CRYPTOPS_SIGN_COMPLETE;
            long avgOpTime = 0;
            String opName = "Sign: ";
            for (int repeat = 0; repeat < runCfg.numSingleOpRepeats; repeat++) {
                CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, 0x0, Util.concat(packetData, Util.concat(plaintext, Rn)));
                avgOpTime += PerfAnalyzeCommand(opName, cmd, channel, runCfg);
            }
            System.out.println(String.format("%s: average time: %d", opName, avgOpTime / runCfg.numSingleOpRepeats));
            transmit(channel, new CommandAPDU(PERF_COMMAND_NONE)); // erase any previous performance stop 

            return Sign(channel, quorumIndex, round, plaintext, Rn, runCfg, false);
        }
    }
         /**/
/*
    private boolean PointAdd(CardChannel channel) throws Exception {
        byte[] PointA = mpcGlobals.G.multiply(BigInteger.valueOf(10)).getEncoded(false);
        byte[] PointB = mpcGlobals.G.multiply(BigInteger.valueOf(20)).getEncoded(false);

        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ADDPOINTS, 0x00, 0x00, Util.concat(PointA, PointB));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }
*/
    private boolean checkSW(ResponseAPDU response) {
        if (response.getSW() != (Consts.SW_SUCCESS & 0xffff)) {
            System.err.printf("Received error status: %02X.\n",
                    response.getSW());
            if (bFailOnAssert) {
                assert (false); // break on error
            }
            return false;
        }
        return true;
    }    
    
    
    private boolean TestNativeECAdd(CardChannel channel, ECPoint point1, ECPoint point2) throws Exception {
        // addPoint
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_TESTECC, (byte) 1, point1.getEncoded(false).length, Util.concat(point1.getEncoded(false), point2.getEncoded(false)));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }

    private boolean TestNativeECMult(CardChannel channel, ECPoint point1, BigInteger scalar) throws Exception {
        // multiply by scalar
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_TESTECC, (byte) 2, point1.getEncoded(false).length, Util.concat(point1.getEncoded(false), scalar.toByteArray()));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }    
}
