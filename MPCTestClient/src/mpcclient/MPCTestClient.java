package mpcclient;


import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;









import ds.ov2.bignat.Bignat;
import ds.ov2.bignat.Convenience;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javacard.framework.AID;

import javafx.util.Pair;
import mpc.Consts;
import mpc.SecP256r1;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class MPCTestClient {
    public final static boolean _DEBUG = true;
    public final static boolean _SIMULATOR = false;
    public final static boolean _PROFILE_PERFORMANCE = false;
    public final static boolean _FAIL_ON_ASSERT = true;
    public final static boolean _IS_BACKDOORED_EXAMPLE = false; // if true, applet is set into example "backdoored" state simulating compromised node with known key
    
    public final static boolean _FIXED_PLAYERS_RNG = false;
    
    
    // Objects
    public static String format = "%-40s:%s%n\n-------------------------------------------------------------------------------\n";

    // Crypto-objects
    // public static EllipticCurve curve;//classic java.sec
    public static ECCurve curve;
    public static BigInteger p;
    public static BigInteger a;
    public static BigInteger b;
    public static BigInteger n;
    public static ECPoint G;
    public static ECParameterSpec ecSpec;

    //public static DS_provider pr = new DS_provider();
    public static BigInteger secret = BigInteger.valueOf(0);
    public static ECPoint PubKey;
    public static ECPoint AggPubKey;
    public static ECPoint R_EC;


    public static ECPoint c1;
    public static ECPoint c2;
    
    static ArrayList<SimulatedPlayer>  players = new ArrayList<>();
	
    static ArrayList<Pair<String, Long>> perfResults = new ArrayList<>();
    static Long m_lastTransmitTime = new Long(0);

    public static ECPoint[] Rands;
    
    static byte[] MPC_APPLET_AID = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0a, (byte) 0x4d, (byte) 0x50, (byte) 0x43, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x74, (byte) 0x31};
    

    public static void main(String[] args) throws Exception {
        try {
            //TestFastModuloViaInverseTrick();
            Integer targetReader = 0;
            if (args.length > 0) {
                targetReader = Integer.getInteger(args[0]);
            }
            
            MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
            runCfg.testCardType = MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL;
            runCfg.testCardType = MPCRunConfig.CARD_TYPE.PHYSICAL;
            runCfg.numSingleOpRepeats = 1000;
            MPCProtocol_playground(runCfg);
        } catch (Exception e) {
                e.printStackTrace();
        }
    }
        
    static void writePerfLog(String operationName, Long time, ArrayList<Pair<String, Long>> perfResults, FileOutputStream perfFile) throws IOException {
        perfResults.add(new Pair(operationName, time));
        perfFile.write(String.format("%s,%d\n", operationName, time).getBytes());
        perfFile.flush();
    }

    static void MPCProtocol_playground(MPCRunConfig runCfg) throws Exception {
        Rands = new ECPoint[runCfg.numPlayers];
        players.clear();
        
	// SecP256r1 curve
	p = new BigInteger(bytesToHex(SecP256r1.p), 16);
	a = new BigInteger(bytesToHex(SecP256r1.a), 16);
	b = new BigInteger(bytesToHex(SecP256r1.b), 16);
	curve = new ECCurve.Fp(p, a, b);
	G = ECPointDeSerialization(SecP256r1.G, 0);
	n = new BigInteger(bytesToHex(SecP256r1.r), 16); // also noted as r
	ecSpec = new ECParameterSpec(curve, G, n);
	//Security.addProvider(pr);
	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SecureRandom rng = new SecureRandom();
		
	// ======================= Secret Sharing Protocol =======================
		 

            /******* Simulate all remaining players *******/
        for (short cardID = (short) (runCfg.thisCardID + 1); cardID < runCfg.numPlayers; cardID++) {
            players.add(new SimulatedPlayer(cardID));
        }
            
        for (int repeat = 0; repeat < runCfg.numWholeTestRepeats; repeat++) {
            /******* Card stuff *******/
            System.out.print("Connecting to card...");
            
            CardChannel channel = Connect(runCfg);
            System.out.println(" Done.");

            // If required, make the applet "backdoored" to demonstrate functionality of 
            // incorrect behavior of malicious attacker
            if (_IS_BACKDOORED_EXAMPLE) {
                SetBackdoorExample(channel, true);
            }

            GetCardInfo(channel);
            
            
            /****** Protocol *******/
            perfResults.clear();
            String logFileName = String.format("MPC_PERF_log_%d.csv", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);
            

            // Setup
            String operationName = "Setting Up the MPC Parameters (INS_SETUP)";
            System.out.format(format, operationName, Setup(channel, runCfg.numPlayers, runCfg.thisCardID));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

            // Reset
            operationName = "Reseting the card to an uninitialized state (INS_RESET)";
            System.out.format(format, operationName, Reset(channel));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

            // Setup again
            operationName = "Setting Up the MPC Parameters (INS_SETUP)";
            System.out.format(format, operationName, Setup(channel, runCfg.numPlayers, runCfg.thisCardID));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

            // BUGBUG: Signature without previous EncryptDecrypt will fail on CryptoObjects.KeyPair.Getxi() - as no INS_KEYGEN_xxx was called
            
            //
            //EC Operations
            //
            //operationName = "EC Point Addition";
            //System.out.format(format, operationName, PointAdd(channel));
            
            //System.exit(0);
/*            
            operationName = "Native ECPoint Add (INS_TESTECC)";
            for (int i = 0; i < runCfg.numSingleOpRepeats; i++) {
                ECPoint pnt1 = randECPoint();
                ECPoint pnt2 = randECPoint();
                System.out.format(format, operationName, TestNativeECAdd(channel, pnt1, pnt2));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            }
            
            operationName = "Native ECPoint scalar multiplication (INS_TESTECC)";
            for (int i = 0; i < runCfg.numSingleOpRepeats; i++) {
                ECPoint pnt1 = randECPoint();
                BigInteger scalar = randomBigNat(256);
                System.out.format(format, operationName, TestNativeECMult(channel, pnt1, scalar));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            }
*/            
            

            //
            // Encrypt / Decrypt
            //
            PerformEncryptDecrypt(BigInteger.TEN, players, channel, perfResults, perfFile);

            // Repeated measurements if required
            for (int i = 0; i < runCfg.numSingleOpRepeats; i++) {
            //    PerformEncryptDecrypt(BigInteger.valueOf(rng.nextInt()), players, channel, perfResults, perfFile);
            }

            //
            // Sign
            //
            //PerformSignature(BigInteger.TEN, players, channel, perfResults, perfFile);
            PerformSignCache(players, channel, perfResults, perfFile);
            PerformSignature(BigInteger.TEN, 1, players, channel, perfResults, perfFile);
            //PerformSignature(BigInteger.valueOf(84125637), 1, players, channel, perfResults, perfFile);
/*            
            // Repeated measurements if required
            long elapsed = -System.currentTimeMillis();
            for (int i = 1; i < runCfg.numSingleOpRepeats; i++) {
                //System.out.println("******** \n RETRY " + i + " \n");
                PerformSignature(BigInteger.valueOf(rng.nextInt()), 1, players, channel, perfResults, perfFile);
            }
            elapsed += System.currentTimeMillis();
            System.out.format("Elapsed: %d ms, time per Sign = %f ms\n", elapsed,  elapsed / (float) runCfg.numSingleOpRepeats);
*/
/*            
            //Aggregate pub keys
            AggPubKey = ECPointDeSerialization(RetrievePubKey(channel), 0);
            for (SimulatedPlayer player : players) {
            	AggPubKey = AggPubKey.add(player.pub_key_EC);
            }
            
            PerformSignCache(players, channel, perfResults, perfFile);
            //PerformSignature(BigInteger.valueOf(rng.nextInt()), 1, players, channel, perfResults, perfFile);
            
            // Repeated measurements if required
            for (int i = 0; i < runCfg.numSingleOpRepeats; i++) {
                System.out.println("******** \n RETRY " + i + " \n");
                PerformSignature(BigInteger.valueOf(rng.nextInt()), i+1, players, channel, perfResults, perfFile);
            }
*/            
          
                    
            System.out.print("Disconnecting from card...");
            channel.getCard().disconnect(true); // Disconnect from the card
            System.out.println(" Done.");

            // Close cvs perf file
            perfFile.close();

            // Save performance results also as latex
            saveLatexPerfLog(perfResults);
        }
    }
    
    /**
     * This integration test is executed in tests - don't make any temporary changes - use 
     * @param runCfg test configurations
     * @throws Exception 
     */
    static void TestMPCProtocol_v20170520(MPCRunConfig runCfg) throws Exception {
        Rands = new ECPoint[runCfg.numPlayers];
        players.clear();

        // SecP256r1 curve
        p = new BigInteger(bytesToHex(SecP256r1.p), 16);
        a = new BigInteger(bytesToHex(SecP256r1.a), 16);
        b = new BigInteger(bytesToHex(SecP256r1.b), 16);
        curve = new ECCurve.Fp(p, a, b);
        G = ECPointDeSerialization(SecP256r1.G, 0);
        n = new BigInteger(bytesToHex(SecP256r1.r), 16); // also noted as r
        ecSpec = new ECParameterSpec(curve, G, n);
        //Security.addProvider(pr);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SecureRandom rng = new SecureRandom();

	// ======================= Secret Sharing Protocol =======================
        // Simulate all remaining players ******
        for (short cardID = (short) (runCfg.thisCardID + 1); cardID < runCfg.numPlayers; cardID++) {
            players.add(new SimulatedPlayer(cardID));
        }

        for (int repeat = 0; repeat < runCfg.numWholeTestRepeats; repeat++) {
            CardChannel channel = Connect(runCfg);
            GetCardInfo(channel);

            perfResults.clear();
            String logFileName = String.format("MPC_PERF_log_%d.csv", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);

            // Setup
            String operationName = "Setting Up the MPC Parameters (INS_SETUP)";
            System.out.format(format, operationName, Setup(channel, runCfg.numPlayers, runCfg.thisCardID));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

            // Reset
            operationName = "Reseting the card to an uninitialized state (INS_RESET)";
            System.out.format(format, operationName, Reset(channel));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

            // Setup again
            operationName = "Setting Up the MPC Parameters (INS_SETUP)";
            System.out.format(format, operationName, Setup(channel, runCfg.numPlayers, runCfg.thisCardID));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

            // Encrypt / Decrypt
            PerformEncryptDecrypt(BigInteger.TEN, players, channel, perfResults, perfFile);
            //Aggregate pub keys
            AggPubKey = ECPointDeSerialization(RetrievePubKey(channel), 0);
            for (SimulatedPlayer player : players) {
                AggPubKey = AggPubKey.add(player.pub_key_EC);
            }
            // Sign (two options)
            PerformSignCache(players, channel, perfResults, perfFile);
            PerformSignature(BigInteger.valueOf(84125637), 1, players, channel, perfResults, perfFile);

            System.out.print("Disconnecting from card...");
            channel.getCard().disconnect(true); // Disconnect from the card
            System.out.println(" Done.");
            
            perfFile.close(); // Close cvs perf file
        }
    }    
    
    static void saveLatexPerfLog(ArrayList<Pair<String, Long>> results) {
        try {
            // Save performance results also as latex
            String logFileName = String.format("MPC_PERF_log_%d.tex", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);
            String tableHeader = "\\begin{tabular}{|l|c|}\n"
                    + "\\hline\n"
                    + "\\textbf{Operation} & \\textbf{Time (ms)} \\\\\n"
                    + "\\hline\n"
                    + "\\hline\n";
            perfFile.write(tableHeader.getBytes());
            for (Pair<String, Long> measurement : results) {
                String operation = measurement.getKey();
                operation = operation.replace("_", "\\_");
                perfFile.write(String.format("%s & %d \\\\ \\hline\n", operation, measurement.getValue()).getBytes());
            }
            String tableFooter = "\\hline\n\\end{tabular}";
            perfFile.write(tableFooter.getBytes());
            perfFile.close();
        } catch (IOException ex) {
            Logger.getLogger(MPCTestClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    static void PerformEncryptDecrypt(BigInteger msgToEncDec, ArrayList<SimulatedPlayer> playersList, CardChannel channel, ArrayList<Pair<String, Long>> perfResultsList, FileOutputStream perfFile) throws NoSuchAlgorithmException, Exception {
        // BUGBUG: INS_KEYGEN_xxx must be called also for Sign, not only for Encrypt
        Long combinedTime = (long) 0;

        // Generate KeyPair in card
        String operationName = "Generate KeyPair (INS_KEYGEN_INIT)";
        System.out.format(format, operationName, GenKeyPair(channel));
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
        combinedTime += m_lastTransmitTime;

        // Retrieve Hash from card
        operationName = "Retrieve Hash of pub key (INS_KEYGEN_RETRIEVE_HASH)";
        System.out.format(format, operationName, RetrievePubKeyHash(channel));
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
        combinedTime += m_lastTransmitTime;

        // Push hash for all our pub keys
        operationName = "Store pub key hash (INS_KEYGEN_STORE_HASH)";
        for (SimulatedPlayer player : players) {
            System.out.format(format, operationName, StorePubKeyHash(channel, player.playerID, player.pub_key_Hash));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }
        // Retrieve card's Public Key
        operationName = "Retrieve Pub Key (INS_KEYGEN_RETRIEVE_PUBKEY)";
        ECPoint pub_share_EC = ECPointDeSerialization(RetrievePubKey(channel), 0);
        System.out.format(format, operationName, bytesToHex(pub_share_EC.getEncoded(false)));
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
        combinedTime += m_lastTransmitTime;

        // Push all public keys
        operationName = "Store Pub Key (INS_KEYGEN_STORE_PUBKEY)";
        for (SimulatedPlayer player : players) {
            System.out.format(format, operationName, StorePubKey(channel, player.playerID, player.pub_key_EC.getEncoded(false)));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }

        // Retrieve Secret
        operationName = "Retrieve Private Key (INS_KEYGEN_RETRIEVE_PRIVKEY)";
        System.out.format(format, operationName, RetrievePrivKey(channel));
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
        combinedTime += m_lastTransmitTime;
        
        // Retrieve Aggregated Y
        operationName = "Retrieve Aggregated Key (INS_KEYGEN_RETRIEVE_AGG_PUBKEY)";
        System.out.format(format, operationName, RetrieveAggPubKey(channel));
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
        combinedTime += m_lastTransmitTime;

        // Encrypt EC Point
        byte[] plaintext = G.multiply(msgToEncDec).getEncoded(false);
        operationName = String.format("Encrypt(%s) (INS_ENCRYPT)", msgToEncDec.toString()); 
        byte[] ciphertext = Encrypt(channel, plaintext, _PROFILE_PERFORMANCE);
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
        combinedTime += m_lastTransmitTime;
        Long combinedTimeDecrypt = combinedTime - m_lastTransmitTime; // Remove encryption time from combined decryption time
        
        writePerfLog("* Combined Encrypt time", combinedTime, perfResults, perfFile);

        if (ciphertext.length > 0) {
            System.out.printf(String.format("%s:", operationName));
            ECPoint c1 = ECPointDeSerialization(ciphertext, 0);
            ECPoint c2 = ECPointDeSerialization(ciphertext, Consts.SHARE_SIZE_CARRY_65);

            // Decrypt EC Point
            // Combine all decryption shares (x_ic)
            ECPoint xc1_EC = curve.getInfinity();
            for (SimulatedPlayer player : players) {
                xc1_EC = xc1_EC.add(c1.multiply(player.priv_key_BI).negate());
            }

            System.out.printf("\n");
            operationName = "Decrypt (INS_DECRYPT)";
            byte[] xc1_share = Decrypt(channel, ciphertext, _PROFILE_PERFORMANCE);
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
            combinedTimeDecrypt += m_lastTransmitTime;

            perfResultsList.add(new Pair("* Combined Decrypt time", combinedTimeDecrypt));        
            writePerfLog("* Combined Decrypt time", combinedTimeDecrypt, perfResults, perfFile);

            System.out.printf(String.format("%s:", operationName));
            xc1_EC = xc1_EC.add(ECPointDeSerialization(xc1_share, 0).negate());
            ECPoint plaintext_EC = c2.add(xc1_EC);

            System.out.format(format, "Decryption successful?:",
                    Arrays.equals(plaintext, plaintext_EC.getEncoded(false)));
            if (_FAIL_ON_ASSERT) {
                assert (Arrays.equals(plaintext, plaintext_EC.getEncoded(false)));
            }
        }
        else {
            System.out.println("ERROR: Failed to retrieve valid encrypted block from card");
            if (_FAIL_ON_ASSERT) {
                assert (false);
            }            
        }
        
    }

    static void PerformSignCache(ArrayList<SimulatedPlayer> playersList, CardChannel channel, ArrayList<Pair<String, Long>> perfResultsList, FileOutputStream perfFile) throws NoSuchAlgorithmException, Exception {

        Bignat counter = new Bignat((short) 2, false);
        Bignat one = new Bignat((short) 2, false);
        one.one();
        counter.one();

        for (int round = 1; round <= Rands.length; round++) {
            Rands[round - 1] = ECPointDeSerialization(RetrieveRI(channel, round), 0);
            System.out.format(format, "Retrieve Ri,n (INS_SIGN_RETRIEVE_RI):", bytesToHex(Rands[round - 1].getEncoded(false)));

            for (SimulatedPlayer player : playersList) {
                Rands[round - 1] = Rands[round - 1].add(ECPointDeSerialization(player.Gen_Rin(counter), 0));
            }
            counter.add(one);
        }
        for (int round = 1; round <= Rands.length; round++) {
            System.out.format("Rands[%d]%s\n", round - 1, bytesToHex(Rands[round - 1].getEncoded(false)));
        }
        System.out.println();
    }
    
    
    static void PerformSignature(BigInteger msgToSign, int i, ArrayList<SimulatedPlayer> playersList, CardChannel channel, ArrayList<Pair<String, Long>> perfResultsList, FileOutputStream perfFile) throws NoSuchAlgorithmException, Exception {
            // Sign EC Point
            byte[] plaintext_sig = G.multiply(msgToSign).getEncoded(false);                     
            
            //String operationName = String.format("Signature(%s) (INS_SIGN)", msgToSign.toString());            
            byte[] signature = Sign(channel, i, plaintext_sig, Rands[i-1].getEncoded(false), _PROFILE_PERFORMANCE);
            
            //Parse s from Card
            Bignat card_s_Bn = new Bignat((short) 32, false);
            card_s_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 0);
            BigInteger card_s_bi = new BigInteger(1, card_s_Bn.as_byte_array());

            //Parse e from Card
            Bignat card_e_Bn = new Bignat((short) 32, false);
            card_e_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 32);
            BigInteger card_e_BI = new BigInteger(1, card_e_Bn.as_byte_array());

            //System.out.println("REALCARD : s:        " + bytesToHex(card_s_Bn.as_byte_array()));
            //System.out.println("REALCARD : e:        " + bytesToHex(card_e_Bn.as_byte_array()) + "\n");
            
            BigInteger sum_s_BI = card_s_bi;
            
            
            //Super bad & ugly way of converting short to Bignat (I've added a proper function in the actual lib)
            Bignat one = new Bignat((short)2);
            one.one();
            Bignat counter = new Bignat((short)2);
            counter.zero();
            for(int j = 0; j <i; j+=1) {
            	counter.add(one);
            }
            
            for (SimulatedPlayer player : playersList) {
                sum_s_BI = sum_s_BI.add(player.Sign(counter, Rands[i-1], plaintext_sig));
                sum_s_BI = sum_s_BI.mod(n);
            }
            
            System.out.format(format, "Verify Signature", Verify(plaintext_sig, AggPubKey, sum_s_BI, card_e_BI));
        
        }
        

    // Card Logistics
    private static CardChannel Connect(MPCRunConfig runCfg) throws Exception {
        switch (runCfg.testCardType) {
            case PHYSICAL: {
                return ConnectPhysicalCard(runCfg.targetReaderIndex);
            }
            case JCOPSIM: {
                return ConnectJCOPSimulator(runCfg.targetReaderIndex);
            }
            case JCARDSIMLOCAL: {
                return ConnectJCardSimLocalSimulator(runCfg.appletToSimulate); 
            }
            case JCARDSIMREMOTE: {
                return null; // Not implemented yet
            }
            default: return null;
        }

    }
    
    
    private static CardChannel ConnectPhysicalCard(int targetReaderIndex) throws Exception {
        // JCOP Simulators
        System.out.print("Looking for physical cards... ");
        return connectToCardByTerminalFactory(TerminalFactory.getDefault(), targetReaderIndex);
    } 

    private static CardChannel ConnectJCOPSimulator(int targetReaderIndex) throws Exception {
        // JCOP Simulators
        System.out.print("Looking for JCOP simulators...");
        int[] ports = new int[]{8050};
        return connectToCardByTerminalFactory(TerminalFactory.getInstance("JcopEmulator", ports), targetReaderIndex);
    }
    
    private static CardChannel ConnectJCardSimLocalSimulator(Class appletClass) throws Exception {
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        CAD cad = new CAD(System.getProperties());
        JavaxSmartCardInterface simulator = (JavaxSmartCardInterface) cad.getCardInterface();
        byte[] installData = new byte[0];
        AID appletAID = new AID(MPC_APPLET_AID, (short) 0, (byte) MPC_APPLET_AID.length);

        AID appletAIDRes = simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        simulator.selectApplet(appletAID);
        return new SimulatedCardChannelLocal(simulator, appletAIDRes);
    }
    
    private static CardChannel connectToCardByTerminalFactory(TerminalFactory factory, int targetReaderIndex) throws CardException {
        List<CardTerminal> terminals = new ArrayList<>();
        
        boolean card_found = false;
        CardTerminal terminal = null;
        Card card = null;
        try { 
            for (CardTerminal t : factory.terminals().list()) {
                terminals.add(t);
                if (t.isCardPresent()) {
                    card_found = true;
                }
            }
            System.out.println("Success.");
        } catch (Exception e) {
            System.out.println("Failed.");
        }

        if (card_found) {
            System.out.println("Cards found: " + terminals);

            terminal = terminals.get(targetReaderIndex); // Prioritize physical card over simulations

            System.out.print("Connecting...");
            card = terminal.connect("*"); // Connect with the card

            System.out.println(" Done.");

            System.out.print("Establishing channel...");
            CardChannel channel = card.getBasicChannel();

            System.out.println(" Done.");

            // Select applet (mpcapplet)
            System.out.println("Smartcard: Selecting applet...");
            
            CommandAPDU cmd = new CommandAPDU(MPC_APPLET_AID);
            ResponseAPDU response = transmit(channel, cmd);
        } else {
            System.out.print("Failed to find physical card.");
        }
        
        if (card != null) {
            return card.getBasicChannel();        
        }
        else {
            return null;
        }
    }



    
        public static short getShort(byte[] buffer, int offset) {
            return ByteBuffer.wrap(buffer, offset, 2).order(ByteOrder.BIG_ENDIAN).getShort();
        }        
        
        private static boolean GetCardInfo(CardChannel channel) throws Exception {
            CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_STATUS, 0, 0);
            ResponseAPDU response = transmit(channel, cmd);

            // Parse response 
            if (response.getSW() == (Consts.SW_SUCCESS & 0xffff)) {
                int offset = 0;
                byte[] data = response.getData();
                System.out.println("---CARD STATE -------");
                assert(data[offset] == Consts.TLV_TYPE_CARDUNIQUEDID);
                offset++;
                short len = getShort(data, offset);
                offset += 2;
                System.out.println(String.format("CardIDLong:\t\t\t %s", toHex(data, offset, len)));
                offset += len;

                assert (data[offset] == Consts.TLV_TYPE_KEYPAIR_STATE);
                offset++;
                assert(getShort(data, offset) == 2);
                offset += 2;
                System.out.println(String.format("KeyPair state:\t\t\t %d", getShort(data, offset)));
                offset += 2;
                assert (data[offset] == Consts.TLV_TYPE_EPHIMERAL_STATE);
                offset++;
                assert (getShort(data, offset) == 2);
                offset += 2;
                System.out.println(String.format("EphiKey state:\t\t\t %d", getShort(data, offset)));
                offset += 2;
                
                assert (data[offset] == Consts.TLV_TYPE_MEMORY);
                offset++;
                assert (getShort(data, offset) == 6);
                offset += 2;
                System.out.println(String.format("MEMORY_PERSISTENT:\t\t %d bytes", getShort(data, offset)));
                offset += 2;
                System.out.println(String.format("MEMORY_TRANSIENT_RESET:\t\t %d bytes", getShort(data, offset)));
                offset += 2;
                System.out.println(String.format("MEMORY_TRANSIENT_DESELECT:\t %d bytes", getShort(data, offset)));
                offset += 2;
                System.out.println("-----------------");
                
                assert (data[offset] == Consts.TLV_TYPE_COMPILEFLAGS);
                offset++;
                assert (getShort(data, offset) == 4);
                offset += 2;
                System.out.println(String.format("Consts.MAX_N_PLAYERS:\t\t %d", getShort(data, offset)));
                offset += 2;
                System.out.println(String.format("DKG.PLAYERS_IN_RAM:\t\t %b", (data[offset] == 0) ? false : true));
                offset++;
                System.out.println(String.format("DKG.COMPUTE_Y_ONTHEFLY:\t\t %b ", (data[offset] == 0) ? false : true));
                offset++;
                System.out.println("-----------------");
                
                assert (data[offset] == Consts.TLV_TYPE_GITCOMMIT);
                offset++;
                len = getShort(data, offset);
                assert (len == 4);
                offset += 2;
                System.out.println(String.format("Git commit tag:\t\t\t 0x%s", toHex(data, offset, len)));
                offset += len;
                System.out.println("-----------------");

                assert (data[offset] == Consts.TLV_TYPE_EXAMPLEBACKDOOR);
                offset++;
                len = getShort(data, offset);
                assert (len == 1);
                offset += 2;
                if (data[offset] == (byte) 0) {
                    System.out.println("Applet is in normal (non-backdoored) state");
                }
                else {
                    System.out.println("WARNING: Applet is in example 'backdoored' state with fixed private key");
                }
                offset += len;
                System.out.println("-----------------");
            }
            
            return checkSW(response);
        }
        
	/* Instructions */
	private static boolean Setup(CardChannel channel, short numPlayers, short thisPlayerID) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SETUP, numPlayers,
				                    thisPlayerID);
		ResponseAPDU response = transmit(channel, cmd);

                return checkSW(response);
	}

	private static boolean Reset(CardChannel channel) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_RESET, 0x00, 0x00);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}

	private static boolean GenKeyPair(CardChannel channel) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_KEYGEN_INIT, 0x00,
				0x00);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}

	private static boolean RetrievePubKeyHash(CardChannel channel)
			throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_KEYGEN_RETRIEVE_HASH,
				0x00, 0x00);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}

	private static boolean StorePubKeyHash(CardChannel channel, int id,
			byte[] hash_arr) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_KEYGEN_STORE_HASH,
				id, 0x00, hash_arr);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}

	private static boolean StorePubKey(CardChannel channel, int id,
			byte[] pub_arr) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_KEYGEN_STORE_PUBKEY,
				id, 0x00, pub_arr);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}

	private static boolean RetrievePrivKey(CardChannel channel)
			throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC,
				                    Consts.INS_KEYGEN_RETRIEVE_PRIVKEY, 0x0, 0x0);
		ResponseAPDU response = transmit(channel, cmd);

		// Store Secret
		Bignat tmp_BN = new Bignat(Consts.SHARE_SIZE_32, false);
		tmp_BN.from_byte_array(Consts.SHARE_SIZE_32, (short) 0, (response.getData()),
				(short) 0);
		secret = Convenience.bi_from_bn(tmp_BN);

		return checkSW(response);
	}

	private static byte[] RetrievePubKey(CardChannel channel) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC,
				                    Consts.INS_KEYGEN_RETRIEVE_PUBKEY, 0x00, 0x00);
		ResponseAPDU response = transmit(channel, cmd);

		PubKey = ECPointDeSerialization(response.getData(), 0); // Store Pub

		// return checkSW(response);
		return response.getData();
	}

	private static boolean RetrieveAggPubKey(CardChannel channel)
			throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC,
				                    Consts.INS_KEYGEN_RETRIEVE_AGG_PUBKEY, 0x00, 0x00);
		ResponseAPDU response = transmit(channel, cmd);

		AggPubKey = ECPointDeSerialization(response.getData(), 0); // Store Pub

		return checkSW(response);
	}

        
    public static byte[] concat(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c = new byte[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }        
    private static boolean TestNativeECAdd(CardChannel channel, ECPoint point1, ECPoint point2) throws Exception {
        // addPoint
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_TESTECC, (byte) 1, point1.getEncoded(false).length, concat(point1.getEncoded(false), point2.getEncoded(false)));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }        
    private static boolean TestNativeECMult(CardChannel channel, ECPoint point1, BigInteger scalar) throws Exception {
        // multiply by scalar
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_TESTECC, (byte) 2, point1.getEncoded(false).length, concat(point1.getEncoded(false), scalar.toByteArray()));
        ResponseAPDU response = transmit(channel, cmd);
        return checkSW(response);
    }
	/*
	 * private static boolean ReconstructPubKey(CardChannel channel) throws
	 * Exception {
	 * 
	 * 
	 * ECPoint sum = ECPointDeSerialization(RetrievePubShare(channel, (short)
	 * 0).toByteArray());
	 * 
	 * for (short pid=1; pid<(NUM_PLAYERS); pid++){ sum =
	 * sum.add(ECPointDeSerialization(RetrievePubShare(channel, (short)
	 * pid).toByteArray())); }
	 * 
	 * //System.out.println("-------------------------------------");
	 * //System.out.println(bytesToHex(PubKey.getEncoded(false)));
	 * //System.out.println(bytesToHex(sum.getEncoded(false))); return
	 * PubKey.equals(sum);//sec_new.equals(secret); }
	 */
        private static byte[] Encrypt(CardChannel channel, byte[] plaintext)
                throws Exception {
            return Encrypt(channel, plaintext, false);
        }
	private static byte[] Encrypt(CardChannel channel, byte[] plaintext, boolean bPerformance)
			throws Exception {
            if (!bPerformance) {            
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ENCRYPT, 0x0, 0x0,
				plaintext);
		ResponseAPDU response = transmit(channel, cmd);
		return response.getData();
            } else {
                for (byte p1 = 1; p1 <= 6; p1++) {
                    CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ENCRYPT, p1, 0x0, plaintext);
                    ResponseAPDU response = transmit(channel, cmd);
                }

                return Encrypt(channel, plaintext, false);
            }                
	}

        private static byte[] Decrypt(CardChannel channel, byte[] ciphertext)
                throws Exception {
            return Decrypt(channel, ciphertext, false);
        }        
	private static byte[] Decrypt(CardChannel channel, byte[] ciphertext, boolean bPerformance)
			throws Exception {

            if (!bPerformance) {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_DECRYPT, 0x0, 0x0,
				ciphertext);
		ResponseAPDU response = transmit(channel, cmd);

		return response.getData();
            }
            else {
                for (byte p1 = 1; p1 <= 3; p1++) {
                    CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_DECRYPT, p1, 0x0,
                            ciphertext);
                    ResponseAPDU response = transmit(channel, cmd);
                }

                return Decrypt(channel, ciphertext, false);                
            }
	}

    private static void SetBackdoorExample(CardChannel channel, boolean bMakeBackdoored)
            throws Exception {

        CommandAPDU cmd;
        if (bMakeBackdoored) {
            // If to be backdoored, set p1 to 0x55
            cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SET_BACKDOORED_EXAMPLE, 0x55, 0x00, 0x00);
        }
        else {
            cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SET_BACKDOORED_EXAMPLE, 0x00, 0x00, 0x00);
        }
        ResponseAPDU response = transmit(channel, cmd);
    }
        

	// /////////////////////////////////////////////////////////////////////////////////
	// //////////////////////// SIGN
	// ////////////////////////////////////////////////////////////////////////////////
/*
	private static boolean GenRI(CardChannel channel) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN_INIT, 0x00, 0x00);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}

	private static boolean RetrieveRIHash(CardChannel channel) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN_RETRIEVE_HASH,
				0x00, 0x00);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}

	private static boolean StoreRIHash(CardChannel channel, int id,
			byte[] hash_arr) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN_STORE_HASH, id,
				0x00, hash_arr);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}
	
	private static boolean StoreRI(CardChannel channel, int id, byte[] Ri_arr) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN_STORE_RI, id,	0x00, Ri_arr);
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}
	
	private static boolean StoreRI_N_Hash(CardChannel channel, int id, byte[] Ri_arr, byte[] Hash_Ri_arr) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN_STORE_RI_N_HASH, id,	0x00, joinArray(Ri_arr, Hash_Ri_arr));
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}

	private static boolean RetrieveKI(CardChannel channel) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.BUGBUG_INS_SIGN_RETRIEVE_KI,
				0x0, 0x0);
		ResponseAPDU response = transmit(channel, cmd);

		// Store Secret
		Bignat tmp_BN = new Bignat(Consts.SHARE_SIZE_32, false);
		tmp_BN.from_byte_array(Consts.SHARE_SIZE_32, (short) 0, (response.getData()),
				(short) 0);
		secret = Convenience.bi_from_bn(tmp_BN);

		return checkSW(response);
	}
*/
	private static byte[] RetrieveRI(CardChannel channel, int i) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN_RETRIEVE_RI,
				i, 0x00);
		ResponseAPDU response = transmit(channel, cmd);

		//We do nothing with the key, as we just use the Aggregated R in the test cases

		// return checkSW(response);
		return response.getData();
	}
/*	
	private static byte[] RetrieveRI_N_Hash(CardChannel channel) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN_RETRIEVE_RI_N_HASH, 0x00, 0x00);
		ResponseAPDU response = transmit(channel, cmd);

		//We do nothing with the key, as we just use the Aggregated R, and the hashes are not validated
		
		// return checkSW(response);
		return response.getData();
	}
	

	private static boolean RetrieveAggR(CardChannel channel) throws Exception {
		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.BUGBUG_INS_SIGN_RETRIEVE_R,
				0x00, 0x00);
		ResponseAPDU response = transmit(channel, cmd);

		R_EC = ECPointDeSerialization(response.getData(), 0); // Store R

		return checkSW(response);
	}
*/
	/*
    private static byte[] Sign(CardChannel channel, byte[] plaintext)
        throws Exception {
        return Sign(channel, plaintext, false);
    }
    */
	
    private static byte[] Sign(CardChannel channel, int round, byte[] plaintext, byte[] Rn, boolean bPerformance) throws Exception {
/*
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
/**/
        if (!bPerformance) {
        	CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, 0x0, concat(plaintext, Rn));
        	ResponseAPDU response = transmit(channel, cmd);

        	return response.getData();
        }
        else {
            // Repeated measurements if required
            for (byte p2 = 1; p2 <= 10; p2++) {
            	CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_SIGN, round, p2, concat(plaintext, Rn));
                    ResponseAPDU response = transmit(channel, cmd);
            }
            return Sign(channel, round, plaintext, Rn, false);
     }
    }
        
        
	private static boolean PointAdd(CardChannel channel) throws Exception {
        byte[] PointA = G.multiply(BigInteger.valueOf(10)).getEncoded(false);
        byte[] PointB = G.multiply(BigInteger.valueOf(20)).getEncoded(false);

		CommandAPDU cmd = new CommandAPDU(Consts.CLA_MPC, Consts.INS_ADDPOINTS, 0x00, 0x00, concat(PointA, PointB));
		ResponseAPDU response = transmit(channel, cmd);
		return checkSW(response);
	}    
    

	private static boolean Verify(byte[] plaintext, ECPoint pubkey, BigInteger s_bi, BigInteger e_bi) throws Exception {

		// Compute rv = sG+eY
		ECPoint rv_EC = G.multiply(s_bi); // sG
		rv_EC = rv_EC.add(pubkey.multiply(e_bi)); // +eY

		// Compute ev = H(m||rv)
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(plaintext);
		md.update(rv_EC.getEncoded(false));
		byte[] ev = md.digest();
		BigInteger ev_bi = new BigInteger(1, ev);
		ev_bi = ev_bi.mod(n);

		//System.out.println(bytesToHex(e_bi.toByteArray()));		
		//System.out.println(bytesToHex(ev_bi.toByteArray()));

        if (_FAIL_ON_ASSERT) {
            assert(e_bi.compareTo(ev_bi) == 0);
        }
		// compare ev with e
		return e_bi.compareTo(ev_bi) == 0;
	}

	/* Utils */
	public static short readShort(byte[] data, int offset) {
		return (short) (((data[offset] << 8)) | ((data[offset + 1] & 0xff)));
	}

	public static byte[] shortToByteArray(int s) {
		return new byte[] { (byte) ((s & 0xFF00) >> 8), (byte) (s & 0x00FF) };
	}

	public static byte[] SerializeBigInteger(BigInteger BigInt) {

		int bnlen = BigInt.bitLength() / 8;

		byte[] large_int_b = new byte[bnlen];
		Arrays.fill(large_int_b, (byte) 0);
		int int_len = BigInt.toByteArray().length;
		if (int_len == bnlen)
			large_int_b = BigInt.toByteArray();
		else if (int_len > bnlen)
			large_int_b = Arrays.copyOfRange(BigInt.toByteArray(), int_len
					- bnlen, int_len);
		else if (int_len < bnlen)
			System.arraycopy(BigInt.toByteArray(), 0, large_int_b,
					large_int_b.length - int_len, int_len);

		return large_int_b;
	}

	public static BigInteger randomBigNat(int maxNumBitLength) {
		Random rnd = new Random();
		BigInteger aRandomBigInt;
		do {
			aRandomBigInt = new BigInteger(maxNumBitLength, rnd);

		} while (aRandomBigInt.compareTo(new BigInteger("1")) < 1);
		return aRandomBigInt;
	}

	private static byte[] ECPointSerialization(ECPoint apoint) {
		// Create a point array that is the size of the two coordinates + prefix
		// used by javacard
		byte[] ECPoint_serial = new byte[1 + 2 * (SecP256r1.KEY_LENGTH / 8)];

		ECFieldElement x = apoint.getAffineXCoord();
		ECFieldElement y = apoint.getAffineYCoord();

		byte[] tempBufferx = new byte[256 / 8];
		if (x.toBigInteger().toByteArray().length == (256 / 8))
			tempBufferx = x.toBigInteger().toByteArray();
		else { // 33
			System.arraycopy(x.toBigInteger().toByteArray(), 1, tempBufferx, 0,
					(256 / 8));
		}

		// src -- This is the source array.
		// srcPos -- This is the starting position in the source array.
		// dest -- This is the destination array.
		// destPos -- This is the starting position in the destination data.
		// length -- This is the number of array elements to be copied.

		byte[] tempBuffery = new byte[256 / 8];
		if (y.toBigInteger().toByteArray().length == (256 / 8))
			tempBuffery = y.toBigInteger().toByteArray();
		else { // 33
			System.arraycopy(y.toBigInteger().toByteArray(), 1, tempBuffery, 0,
					(256 / 8));
		}

		byte[] O4 = { (byte) 0x04 };
		System.arraycopy(O4, 0, ECPoint_serial, 0, 1);

		// copy x into start of ECPoint_serial (from pos 1, copy x.length bytes)
		System.arraycopy(tempBufferx, 0, ECPoint_serial, 1, tempBufferx.length);

		// copy y into end of ECPoint_serial (from pos x.length+1, copy y.length
		// bytes)
		System.arraycopy(tempBuffery, 0, ECPoint_serial,
				1 + tempBufferx.length, tempBuffery.length);

		// System.out.println((bytesToHex(ECPoint_serial)));

		return ECPoint_serial;
	}

	private static ECPoint ECPointDeSerialization(byte[] serialized_point,
			int offset) {

		byte[] x_b = new byte[256 / 8];
		byte[] y_b = new byte[256 / 8];

		// System.out.println("Serialized Point: " + toHex(serialized_point));

		// src -- This is the source array.
		// srcPos -- This is the starting position in the source array.
		// dest -- This is the destination array.
		// destPos -- This is the starting position in the destination data.
		// length -- This is the number of array elements to be copied.

		System.arraycopy(serialized_point, offset + 1, x_b, 0, Consts.SHARE_SIZE_32);
		BigInteger x = new BigInteger(bytesToHex(x_b), 16);
		// System.out.println("X:" + toHex(x_b));
		System.arraycopy(serialized_point, offset + (Consts.SHARE_SIZE_32 + 1), y_b, 0, Consts.SHARE_SIZE_32);
		BigInteger y = new BigInteger(bytesToHex(y_b), 16);
		// System.out.println("Y:" + toHex(y_b));

		ECPoint point = curve.createPoint(x, y);

		return point;
	}

	private static ECPoint randECPoint() throws Exception {
		ECParameterSpec ecSpec_named = ECNamedCurveTable
				.getParameterSpec("secp256r1"); // NIST P-256
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
		kpg.initialize(ecSpec_named);
		KeyPair apair = kpg.generateKeyPair();
		ECPublicKey apub = (ECPublicKey) apair.getPublic();
		return apub.getQ();
	}

	private static boolean checkSW(ResponseAPDU response) {
		if (response.getSW() != (Consts.SW_SUCCESS & 0xffff)) {
			System.err.printf("Received error status: %02X.\n",
					response.getSW());
			// System.exit(1);
                        if (_FAIL_ON_ASSERT) {
                            assert(false); // break on error
                        }
			return false;
		}
		return true;
	}

	private static ResponseAPDU transmit(CardChannel channel, CommandAPDU cmd)
			throws CardException {
		if (_DEBUG == true)
			log(cmd);
                
                long elapsed = -System.currentTimeMillis();
		ResponseAPDU response = channel.transmit(cmd);
                elapsed += System.currentTimeMillis();
                m_lastTransmitTime = elapsed;
		if (_DEBUG == true)
			log(response, elapsed);

		return response;
	}

	private static void log(CommandAPDU cmd) {
		System.out.printf("--> %s\n", toHex(cmd.getBytes()),
				cmd.getBytes().length);
	}

        private static void log(ResponseAPDU response, long time) {
            String swStr = String.format("%02X", response.getSW());
            byte[] data = response.getData();
            if (data.length > 0) {
                System.out.printf("<-- %s %s (%d)\n", toHex(data), swStr,
                        data.length);
            } else {
                System.out.printf("<-- %s\n", swStr);
            }
            if (time > 0) {
                System.out.printf(String.format("Elapsed time %d ms\n", time));
            }
        }        
	private static void log(ResponseAPDU response) {
            log(response, 0);
	}
/* unused
	private static Card waitForCard(CardTerminals terminals)
			throws CardException {
		while (true) {
			for (CardTerminal ct : terminals
					.list(CardTerminals.State.CARD_INSERTION)) {

				return ct.connect("*");
			}
			terminals.waitForChange();
		}
	}
*/        

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
	
    static byte[] joinArray(byte[]... arrays) {
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
    
    /*
    private static Pair<BigInteger, BigInteger> FastSign(byte[] plaintext, CardChannel channel, FileOutputStream perfFile) throws Exception {
    	// Push all our r's and Hashes for the next round
        String operationName;
        for (SimulatedPlayer player : players) {
        	byte[] tmp_Ri_arr = player.Ri_EC.getEncoded(false);
        	 //Sends the current Ri, and the hash of the next Ri
            operationName = "Store Ri + Next Hash";
            System.out.format(format, operationName,(StoreRI_N_Hash(channel, player.playerID, tmp_Ri_arr, player.Ri_Hash_pre)));
            perfResults.add(new Pair(operationName, m_lastTransmitTime));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
        }
        
        // Retrieve card's r_i
        operationName = "Retrieve ri+hash";
        System.out.format(format, operationName, bytesToHex(RetrieveRI_N_Hash(channel)));
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
        
        // Retrieve aggregated R
        operationName = "Retrieve Aggregated R";
        System.out.format(format, operationName, (RetrieveAggR(channel)));
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

        byte[] signature = Sign(channel, plaintext, _PROFILE_PERFORMANCE);
        operationName = "Signature";
        System.out.format(format, operationName, bytesToHex(signature));
        writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
		
        //Parse s from Card
        Bignat card_s_Bn = new Bignat((short) 32, false);
		card_s_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 0);
		BigInteger card_s_bi = new BigInteger(1, card_s_Bn.as_byte_array());
                 
   		//Parse e from Card
		Bignat card_e_Bn = new Bignat((short) 32, false);
   		card_e_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 32);
   		BigInteger card_e_BI = new BigInteger(1, card_e_Bn.as_byte_array());
       
        BigInteger sum_s_BI = card_s_bi;
        for (SimulatedPlayer player : players) {
        	sum_s_BI = sum_s_BI.add(player.Sign(R_EC, plaintext));
        	//sum_s_BI = sum_s_BI.add(player.k_Bn.subtract(card_e_BI.multiply(player.priv_key_BI)));
        	sum_s_BI = sum_s_BI.mod(n);
            player.Gen_next_Ri(); //Current pair <- Next pair, plus a new pair is generated.
        }
        
        return new Pair<>(sum_s_BI, card_e_BI);
    }
	*/
    
    static byte[] r_for_BigInteger = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x43, (byte) 0x19, (byte) 0x05, (byte) 0x52, (byte) 0xdf, (byte) 0x1a, (byte) 0x6c, (byte) 0x21, (byte) 0x01, (byte) 0x2f, (byte) 0xfd, (byte) 0x85, (byte) 0xee, (byte) 0xdf, (byte) 0x9b, (byte) 0xfe, (byte) 0x67};
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
    
    
    public static byte[] trimLeadingZeroes(byte[] array) {
        short startOffset = 0;    
        for (int i = 0; i < array.length; i++) {
            if (array[i] != 0) {
                break;
            }
            else {
                // still zero
                startOffset++;
            }
        }
        
        byte[] result = null;
        if (startOffset == 0) {
            result = array;
        }  
        else {
            result = new byte[array.length - startOffset];
            System.arraycopy(array, startOffset, result, 0, result.length);
        }
        return result;
    }
    
    static byte[] testNonOptimizedModuloBignat(byte[] n, byte[] r, byte[] expectedResult) {
        Bignat modulo_Bn = new Bignat((short) Consts.RND_SIZE, false);
        modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) (0), SecP256r1.r, (short) 0);
        Bignat xe_Bn = new Bignat(Consts.SHARE_SIZE_64, false);
        xe_Bn.from_byte_array((short) xe_Bn_testInput1.length, (short) (0), xe_Bn_testInput1, (short) 0);

        xe_Bn.remainder_divide(modulo_Bn, null);
        
        byte[] result = xe_Bn.as_byte_array();
        
        // Trim leading zeroes from result array 
        result = trimLeadingZeroes(result);
        
        assert (Arrays.equals(result, expectedResult));
        
        return result;
    }
    /*
    static byte[] testOptimizedModuloBignat(byte[] n, byte[] r, byte[] expectedResult) {
        Bignat modulo_Bn = new Bignat((short) Consts.RND_SIZE, false);
        modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) (0), SecP256r1.r, (short) 0);
        Bignat xe_Bn = new Bignat(Consts.SHARE_SIZE_64, false);
        xe_Bn.from_byte_array((short) xe_Bn_testInput1.length, (short) (0), xe_Bn_testInput1, (short) 0);

        xe_Bn.remainder_divide(modulo_Bn, null);
        
        Bignat.fastResizeArray = new byte[Consts.MAX_BIGNAT_SIZE];
        // xe_Bn_test % modulo_Bn = xe_Bn_test - ((xe_Bn_test * aBn) >> k) * modulo_Bn
        Bignat resBn = new Bignat((short) 101, false);
        Bignat input = new Bignat((short) xe_Bn_testInput1.length, false);
        input.from_byte_array((short) xe_Bn_testInput1.length, (short) (0), xe_Bn_testInput1, (short) 0);
        Bignat aBn = new Bignat((short) r_for_BigInteger.length, false);
        aBn.from_byte_array((short) r_for_BigInteger.length, (short) (0), r_for_BigInteger, (short) 0);
        //(n * a)
        resBn.mult(aBn, input);
        System.out.format("n * a = %s\n", bytesToHex(resBn.as_byte_array()));
        // ((n * a) >> k)
        short SHIFT_BYTES_AAPROX = (short) 65;
        resBn.shiftBytes_right(SHIFT_BYTES_AAPROX); // 520 == 65*8
        System.out.format("((n * a) >> k) = %s\n", bytesToHex(resBn.as_byte_array()));
        System.out.format("So far matches\n");
        // ((n * a) >> k) * r
        //short res2Len = (short) (resBn.size() - SHIFT_BYTES_AAPROX);
        short res2Len = (short) ((short) 97 - SHIFT_BYTES_AAPROX);
        Bignat resBn2 = new Bignat(res2Len, false);

        resBn2.from_byte_array(res2Len, (short) 0, resBn.as_byte_array(), (short) (SHIFT_BYTES_AAPROX + 4));
        Bignat resBn3 = new Bignat((short) 101, false);

        //resBn3.mult(aBn, resBn2);
        resBn3.mult(modulo_Bn, resBn2);
        System.out.format("resBn2 = ((n * a) >> k) = %s\n", bytesToHex(resBn2.as_byte_array()));
        System.out.format("r = %s\n", bytesToHex(modulo_Bn.as_byte_array()));
        System.out.format("((n * a) >> k) * r = %s\n", bytesToHex(resBn3.as_byte_array()));
        // n - ((n * a) >> k) * r
        byte[] result = input.as_byte_array();
        byte[] inter = resBn3.as_byte_array();
        Bignat.subtract(result, (short) 0, (short) result.length, inter, (short) 0, (short) inter.length);
        System.out.format("n - ((n * a) >> k) * r = %s\n", bytesToHex(result));

        
        assert(Arrays.equals(result, expectedResult));
        
        return result;
    }
    */
    /*
    static byte[] testOptimizedModuloBignat2(byte[] n, byte[] r, byte[] expectedResult) {
        Bignat modulo_Bn = new Bignat((short) Consts.RND_SIZE, false);
        modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) (0), SecP256r1.r, (short) 0);

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
        
        System.out.format("a1 x (2^k mod r) + a0  = %s\n", bytesToHex(resBn.as_byte_array()));
        testModuloBigInteger();

        return resBn.as_byte_array();
    }    
    */
    static void testModuloBigInteger() {

// Non-Optimized modulo with Java's BigInteger     
        BigInteger a2 = new BigInteger(1, xe_Bn_testInput1);
        BigInteger r2 = new BigInteger(1, mpc.SecP256r1.r);
        a2.negate();
        BigInteger res2 = a2.mod(r2);
        System.out.format("a2 mod r2 = %s\n", res2.toString(16));
// Non-Optimized modulo with Java's BigInteger     

// Optimized but with Java's BigInteger        
        System.out.format("\n*********** BEGIN: Modulo trick with BigInteger ********\n");
        // n % r = n - ((n * a) >> k) * r
        BigInteger testIn1 = new BigInteger(1, xe_Bn_testInput1);
        // Important: approx_a == mpc.SecP256r1.r but with one additional integer coding the sign
        BigInteger a3 = new BigInteger(1, r_for_BigInteger);
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
    }
    
    byte[] shifted_r = {(byte) 0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xbc, (byte)0xe6, (byte)0xfa, (byte)0xad, (byte)0xa7, (byte)0x17, (byte)0x9e, (byte)0x84, (byte)0xf3, (byte)0xb9, (byte)0xca, (byte)0xc2, (byte)0xfc, (byte)0x63, (byte)0x25, (byte)0x51, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};    
    static void testShiftRSAModuloTrick() {
        // n mod r == ((n<<k)^1 mod (r << k) ) >> k
        
        Bignat modulo_Bn = new Bignat((short) Consts.RND_SIZE, false);
        modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) (0), SecP256r1.r, (short) 0);

    }
    
    
    /**
     * Function demonstrate computation of modulo of big numbers realized via multiplication trick (which can be done with RSA)
     * // n % r = n - ((n * a) >> k) * r
     * Our constant r is 0xffffffff0000000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
     * n is 
     */
    /*
    static void TestFastModuloViaInverseTrick() {
        
        BigInteger a2 = new BigInteger("1", 10);
        a2 = a2.shiftLeft(256);
        BigInteger r2 = new BigInteger(1, mpc.SecP256r1.r);
        a2.negate();
        BigInteger res2 = a2.mod(r2);
        System.out.format("a2 mod r2 = %s\n", res2.toString(16));

        byte[] result;
      //  byte[] result = testOptimizedModuloBignat(xe_Bn_testInput1, SecP256r1.r, xe_Bn_testOutput1);

        result = testOptimizedModuloBignat2(xe_Bn_testInput1, SecP256r1.r, xe_Bn_testOutput1);
        
// Bignat Modulo non-optimized        
        System.out.format("\n*********** BEGIN: Modulo non-optimized with Bignat  ********\n");
        result = testNonOptimizedModuloBignat(xe_Bn_testInput1, SecP256r1.r, xe_Bn_testOutput1);
        System.out.format("testInput1 mod r = %s\n", bytesToHex(result));
        result = testNonOptimizedModuloBignat(xe_Bn_testInput2, SecP256r1.r, xe_Bn_testOutput2);
        System.out.format("testInput2 mod r = %s\n", bytesToHex(result));

        System.out.format("*********** END: Modulo non-optimized with Bignat  ********\n");
// End Modulo non-optimized     
   

// Bignat modulo trick Optimized      
        System.out.format("\n*********** BEGIN: Modulo trick with Bignat  ********\n");
        result = testOptimizedModuloBignat(xe_Bn_testInput1, SecP256r1.r, xe_Bn_testOutput1);
        System.out.format("testInput1 mod r = %s\n", bytesToHex(result));
        result = testOptimizedModuloBignat(xe_Bn_testInput2, SecP256r1.r, xe_Bn_testOutput1);
        System.out.format("testInput2 mod r = %s\n", bytesToHex(result));

        System.out.format("*********** END: Modulo trick with Bignat  ********\n");
// end Bignat modulo Optimized   
        
        
        //testModuloBigInteger();
        
    }
    */
    
    static byte[] citConst = {(byte) 0x01, (byte) 0x00, (byte) 0x01};
    
    static void TestRSAMult() {
        BigInteger a = new BigInteger("03BD286B6A221F1BFC08C6C5B03F0BEA6C38BEBACF202AAADFACA3703832F8CCE0A87088E91721A34C8D0B9711980246045640A1AE34C1FB7DB84528C61BC6D0", 16);
        BigInteger r = new BigInteger("ffffffff0000000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
        BigInteger res = a.mod(r);
        System.out.format("a mod r = %s\n", res.toString(16));
        
        
        
/*        
        
        
        Bignat e_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
        Bignat s_Bn = new Bignat(Consts.SHARE_SIZE_32, false);
        Bignat xe_Bn = new Bignat(Consts.SHARE_SIZE_64, false);
        
        try {
            Bignat.allocate();
        }
        catch (Exception e) {
            
        }
        
        Bignat modulo_Bn = new Bignat((short) Consts.RND_SIZE, false);
        modulo_Bn.from_byte_array((short) SecP256r1.r.length, (short) (0), SecP256r1.r, (short) 0);
        
        
        e_Bn.athousand();
        System.out.format("e_Bn = %s\n", bytesToHex(e_Bn.as_byte_array()));
        s_Bn.setLastByte((byte) 13);
        System.out.format("s_Bn = %s\n", bytesToHex(s_Bn.as_byte_array()));
        
        e_Bn.remainder_divide(s_Bn, null);

        System.out.format("e_Bn = %s\n", bytesToHex(e_Bn.as_byte_array()));
///////////////////////
        e_Bn.athousand();
        byte[] array = e_Bn.as_byte_array();
        array[0] = (byte) 0xff;
        s_Bn.setLastByte((byte) 13);
        
        xe_Bn.from_byte_array((short) xe_Bn_test.length, (short) (0), xe_Bn_test, (short) 0);
        xe_Bn.remainder_divide(modulo_Bn, null);
        System.out.format("xe_Bn = %s\n", bytesToHex(xe_Bn.as_byte_array()));
///////////////////////        
        
        xe_Bn.from_byte_array((short) xe_Bn_test.length, (short) (0), xe_Bn_test, (short) 0);
        
        xe_Bn.remainder_divide(modulo_Bn, null);
        
        System.out.format("xe_Bn = %s\n", bytesToHex(xe_Bn.as_byte_array()));
        
        
        Bignat cit = new Bignat((short) 3, false);
        
        cit.from_byte_array((short) citConst.length, (short) 0, citConst, (byte) 0);
        
        byte[] mult_resultArray = new byte[96];
        // Copy x to the end of mult_resultArray
        short xOffset = (short) ((short) (mult_resultArray.length - e_Bn.size()) - 1);
        Util.arrayCopyNonAtomic(e_Bn.as_byte_array(), (short) 0, mult_resultArray, xOffset, e_Bn.size());
        //xOffset--; // Add one extra 0 for potential carry during add
        short xLen = e_Bn.size();
        //short xLen = (short) (e_Bn.size() + 1);        
        
        byte[] y = s_Bn.as_byte_array();

        Bignat.add(mult_resultArray, xOffset, xLen, y, (short) 0, (short) y.length);
        
        xe_Bn.mult(e_Bn, s_Bn);
        
        xe_Bn.shiftBytes_right((short) 8);
       
        System.out.format("xe_Bn = %s\n", bytesToHex(xe_Bn.as_byte_array()));
        
        Bignat xe_Bn2 = new Bignat(Consts.SHARE_SIZE_64, false);
        xe_Bn2.multRSATrick(e_Bn, s_Bn);
        System.out.format("xe_Bn2 = %s\n", bytesToHex(xe_Bn.as_byte_array()));
*/        
    }

    /* del 20170203                   
     // Sign EC Point
     byte[] plaintext_sig = G.multiply(BigInteger.TEN).getEncoded(false);

     //////////////////////////Signature 1////////////////////////

                    
     // Generate Ephimeral key in simulated cards
     for (SimulatedPlayer player : players) {
     player.Gen_Ri(); //Fresh ephimeral pair 
     }
                    
     // Generate Ephimeral key in card (r)
     System.out.format(format, "Generate r_i (INS_SIGN_INIT):", (GenRI(channel)));
     perfResults.add(new Pair("Generate r_i:", m_lastTransmitTime));

     // Generate Ephimeral key in simulated cards
     for (SimulatedPlayer player : players) {
     player.Gen_Ri(); //Fresh ephimeral pair 
     }
                    
     // Retrieve Hash from card
     System.out.format(format, "Retrieve Hash of r_i (INS_SIGN_RETRIEVE_HASH):", (RetrieveRIHash(channel)));
     perfResults.add(new Pair("Retrieve Hash of r_i:", m_lastTransmitTime));

     //This is done only on the first round
     // Push hash for all our Ephimeral keys (r)
     for (SimulatedPlayer player : players) {
     System.out.format(format, "Store our r_i hash (INS_SIGN_STORE_HASH):",(StoreRIHash(channel, player.playerID, player.Ri_Hash)));
     perfResults.add(new Pair("Store our r_i hash:", m_lastTransmitTime));
     }
                    
                    
     // Retrieve card's r_i
     System.out.format(format, "Retrieve ri+hash (INS_SIGN_RETRIEVE_RI_N_HASH):", bytesToHex(RetrieveRI_N_Hash(channel)));
     perfResults.add(new Pair("Retrieve ri+hash", m_lastTransmitTime));

                    
     // Push all our r + next hash
     //for (SimulatedPlayer player : players) {
     //	byte[] tmp_Ri_arr = player.Ri_EC.getEncoded(false);
     //	 //Sends the current Ri, and the hash of the next Ri
     //    System.out.format(format, "Store Ri + Next Hash:",(StoreRI_N_Hash(channel, player.playerID, tmp_Ri_arr, player.Ri_Hash_pre)));
     //    perfResults.add(new Pair("Store Ri + Next Hash:", m_lastTransmitTime));
     //}
                    
                    
     // Push all our r
     for (SimulatedPlayer player : players) {
     byte[] tmp_Ri_arr = player.Ri_EC.getEncoded(false);
     //Sends the current Ri, and the hash of the next Ri
     System.out.format(format, "Store Ri (INS_SIGN_STORE_RI):",(StoreRI(channel, player.playerID, tmp_Ri_arr)));
     perfResults.add(new Pair("Store Ri:", m_lastTransmitTime));
     }
                    
                    
     //Retrieve card's k
     //System.out.format(format, "Retrieve k:", (RetrieveKI(channel)));
     //perfResults.add(new Pair("Retrieve k:", m_lastTransmitTime));

     //Retrieve aggregated R
     System.out.format(format, "Retrieve Aggregated R (INS_SIGN_RETRIEVE_R):",(RetrieveAggR(channel)));
     perfResults.add(new Pair("Retrieve Aggregated R:", m_lastTransmitTime));

     byte[] signature = Sign(channel, plaintext_sig, _PROFILE_PERFORMANCE);
     perfResults.add(new Pair("Signature (INS_SIGN):", m_lastTransmitTime));
     System.out.format(format, "Signature:", bytesToHex(signature));
					
     //Parse s from Card
     Bignat card_s_Bn = new Bignat((short) 32, false);
     card_s_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 0);
     BigInteger card_s_bi = new BigInteger(1, card_s_Bn.as_byte_array());

     //Parse e from Card
     Bignat card_e_Bn = new Bignat((short) 32, false);
     card_e_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 32);
     BigInteger card_e_BI = new BigInteger(1, card_e_Bn.as_byte_array());
                   
     BigInteger sum_s_BI = card_s_bi;
     for (SimulatedPlayer player : players) {
     sum_s_BI = sum_s_BI.add(player.Sign(R_EC, plaintext_sig));
     //sum_s_BI = sum_s_BI.add(player.k_Bn.subtract(card_e_BI.multiply(player.priv_key_BI)));
     sum_s_BI = sum_s_BI.mod(n);
     player.Gen_next_Ri(); //Current pair <- Next pair, plus a new pair is generated.
     }
                    
     System.out.format(format, "Verify Signature", Verify(plaintext_sig, sum_s_BI, card_e_BI));
                    
                    
     //					////////////////////////Signature 2////////////////////////
                    
     plaintext_sig = G.multiply(BigInteger.valueOf(84125637)).getEncoded(false);
                    
     // Generate Ephimeral key in simulated cards
     for (SimulatedPlayer player : players) {
     player.Gen_Ri(); //Fresh ephimeral pair 
     }
                    
     // Generate Ephimeral key in card (r)
     System.out.format(format, "Generate r_i:", (GenRI(channel)));
     perfResults.add(new Pair("Generate r_i:", m_lastTransmitTime));

     // Generate Ephimeral key in simulated cards
     for (SimulatedPlayer player : players) {
     player.Gen_Ri(); //Fresh ephimeral pair 
     }
                    
     // Retrieve Hash from card
     System.out.format(format, "Retrieve Hash of r_i:", (RetrieveRIHash(channel)));
     perfResults.add(new Pair("Retrieve Hash of r_i:", m_lastTransmitTime));

     // This is done only on the first round
     // Push hash for all our Ephimeral keys (r)
     for (SimulatedPlayer player : players) {
     System.out.format(format, "Store our r_i hash:",(StoreRIHash(channel, player.playerID, player.Ri_Hash)));
     perfResults.add(new Pair("Store our r_i hash:", m_lastTransmitTime));
     }
                             
     // Retrieve card's r_i
     System.out.format(format, "Retrieve ri+hash:", bytesToHex(RetrieveRI_N_Hash(channel)));
     perfResults.add(new Pair("Retrieve ri+hash", m_lastTransmitTime));
                    
                    
     // Push all our r
     for (SimulatedPlayer player : players) {
     byte[] tmp_Ri_arr = player.Ri_EC.getEncoded(false);
     //Sends the current Ri, and the hash of the next Ri
     System.out.format(format, "Store Ri:",(StoreRI(channel, player.playerID, tmp_Ri_arr)));
     perfResults.add(new Pair("Store Ri:", m_lastTransmitTime));
     }
                    

     //Retrieve aggregated R
     System.out.format(format, "Retrieve Aggregated R:",(RetrieveAggR(channel)));
     perfResults.add(new Pair("Retrieve Aggregated R:", m_lastTransmitTime));

     signature = Sign(channel, plaintext_sig, _PROFILE_PERFORMANCE);
     perfResults.add(new Pair("Signature:", m_lastTransmitTime));
     System.out.format(format, "Signature:", bytesToHex(signature));
					
     //Parse s from Card
     card_s_Bn = new Bignat((short) 32, false);
     card_s_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 0);
     card_s_bi = new BigInteger(1, card_s_Bn.as_byte_array());
                             
     //Parse e from Card
     card_e_Bn = new Bignat((short) 32, false);
     card_e_Bn.from_byte_array((short) 32, (short) 0, signature, (short) 32);
     card_e_BI = new BigInteger(1, card_e_Bn.as_byte_array());
                   
     sum_s_BI = card_s_bi;
     for (SimulatedPlayer player : players) {
     sum_s_BI = sum_s_BI.add(player.Sign(R_EC, plaintext_sig));
     //sum_s_BI = sum_s_BI.add(player.k_Bn.subtract(card_e_BI.multiply(player.priv_key_BI)));
     sum_s_BI = sum_s_BI.mod(n);
     player.Gen_next_Ri(); //Current pair <- Next pair, plus a new pair is generated.
     }
                    
     System.out.format(format, "Verify Signature", Verify(plaintext_sig, sum_s_BI, card_e_BI));
                    
     */
    /*
     //////////////////////////Signature 2////////////////////////
     plaintext_sig = G.multiply(BigInteger.valueOf(84125637)).getEncoded(false);
     Pair<BigInteger, BigInteger> sig_pair = FastSign(plaintext_sig, channel);
     System.out.format(format, "Verify Signature", Verify(plaintext_sig, sig_pair.getKey(), sig_pair.getValue()));
                    
     //////////////////////////Signature 3////////////////////////
     plaintext_sig = G.multiply(BigInteger.valueOf(55854)).getEncoded(false);
     sig_pair = FastSign(plaintext_sig, channel);
     System.out.format(format, "Verify Signature", Verify(plaintext_sig, sig_pair.getKey(), sig_pair.getValue()));               

     //////////////////////////Signature 4////////////////////////
     plaintext_sig = G.multiply(BigInteger.valueOf(888972)).getEncoded(false);
     sig_pair = FastSign(plaintext_sig, channel);
     System.out.format(format, "Verify Signature", Verify(plaintext_sig, sig_pair.getKey(), sig_pair.getValue()));

     //////////////////////////Signature 5////////////////////////
     plaintext_sig = G.multiply(BigInteger.valueOf(283372)).getEncoded(false);
     sig_pair = FastSign(plaintext_sig, channel);
     System.out.format(format, "Verify Signature", Verify(plaintext_sig, sig_pair.getKey(), sig_pair.getValue()));                    
                    
     //////////////////////////Signature 6////////////////////////
     plaintext_sig = G.multiply(BigInteger.valueOf(108972)).getEncoded(false);
     sig_pair = FastSign(plaintext_sig, channel);
     System.out.format(format, "Verify Signature", Verify(plaintext_sig, sig_pair.getKey(), sig_pair.getValue()));                    
     */
    
}
