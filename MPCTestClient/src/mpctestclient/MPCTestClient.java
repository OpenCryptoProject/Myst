package mpctestclient;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import javax.smartcardio.CardChannel;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import ds.ov2.bignat.Bignat;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javafx.util.Pair;
import mpc.Consts;
import mpc.PM;
import mpc.jcmathlib.*;

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

    public final static short QUORUM_INDEX = 0;

    // Objects
    public static String format = "%-40s:%s%n\n-------------------------------------------------------------------------------\n";

    // Crypto-objects
    static MPCGlobals mpcGlobals = new MPCGlobals();

    static byte[] MPC_APPLET_AID = {(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x0a, (byte) 0x4d, (byte) 0x50, (byte) 0x43, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6c, (byte) 0x65, (byte) 0x74, (byte) 0x31};

    // Performance testing variables
    static ArrayList<Pair<String, Long>> perfResults = new ArrayList<>();
    static Long m_lastTransmitTime = new Long(0);
    public static HashMap<Short, String> PERF_STOP_MAPPING = new HashMap<>();
    public static byte[] PERF_COMMAND = {Consts.CLA_MPC, Consts.INS_PERF_SETSTOP, 0, 0, 2, 0, 0};
    //public static byte[] APDU_RESET = {(byte) 0xB0, (byte) 0x03, (byte) 0x00, (byte) 0x00};
    public static final byte[] PERF_COMMAND_NONE = {Consts.CLA_MPC, Consts.INS_PERF_SETSTOP, 0, 0, 2, 0, 0};
    static final String PERF_TRAP_CALL = "PM.check(PM.";
    static final String PERF_TRAP_CALL_END = ");";
    public final static boolean MODIFY_SOURCE_FILES_BY_PERF = true;
    // end Performance testing variables

    public static void main(String[] args) throws Exception {
        try {
            buildPerfMapping();

            MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
            //runCfg.testCardType = MPCRunConfig.CARD_TYPE.JCARDSIMLOCAL;
            runCfg.testCardType = MPCRunConfig.CARD_TYPE.PHYSICAL;
            runCfg.numSingleOpRepeats = 1;
            //runCfg.numWholeTestRepeats = 10; more than one repeat will fail on simulator due to change of address of allocated objects, runs ok on real card
            runCfg.numPlayers = 4;
            runCfg.cardName = "gd60";

            MPCProtocol_demo(runCfg);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void writePerfLog(String operationName, Long time, ArrayList<Pair<String, Long>> perfResults, FileOutputStream perfFile) throws IOException {
        perfResults.add(new Pair(operationName, time));
        perfFile.write(String.format("%s,%d\n", operationName, time).getBytes());
        perfFile.flush();
    }

    static void MPCProtocol_demo(MPCRunConfig runCfg) throws Exception {
        String experimentID = String.format("%d", System.currentTimeMillis());
        runCfg.perfFile = new FileOutputStream(String.format("MPC_DETAILPERF_log_%s.csv", experimentID));

        // Prepare globals
        mpcGlobals.Rands = new ECPoint[runCfg.numPlayers];
        mpcGlobals.players.clear();

        // Prepare SecP256r1 curve
        prepareECCurve(mpcGlobals);

        // Obtain list of all connected MPC cards
        System.out.print("Connecting to MPC cards...");
        ArrayList<CardChannel> cardsList = new ArrayList<>();
        CardManagement.ConnectAllPhysicalCards(runCfg.appletAID, cardsList);
        // Create card contexts, fill cards IDs
        short cardID = runCfg.thisCardID;
        for (CardChannel channel : cardsList) {
            CardMPCPlayer cardPlayer = new CardMPCPlayer(channel, format, m_lastTransmitTime, _FAIL_ON_ASSERT, mpcGlobals.curve);
            // If required, make the applet "backdoored" to demonstrate functionality of incorrect behavior of a malicious attacker
            if (_IS_BACKDOORED_EXAMPLE) {
                cardPlayer.SetBackdoorExample(channel, true);
            }
            // Retrieve card information
            cardPlayer.GetCardInfo();
            mpcGlobals.players.add(cardPlayer);
            cardID++;
        }
        System.out.println(" Done.");

        // Simulate all remaining participants in protocol in addition to MPC card(s) 
        for (; cardID < runCfg.numPlayers; cardID++) {
            mpcGlobals.players.add(new SimulatedMPCPlayer(cardID, mpcGlobals.G, mpcGlobals.n, mpcGlobals.curve));
        }

        for (int repeat = 0; repeat < runCfg.numWholeTestRepeats; repeat++) {
            perfResults.clear();
            String logFileName = String.format("MPC_PERF_log_%d.csv", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);

            //
            // Setup card(s)
            //
            short playerIndex = 0;
            for (MPCPlayer player : mpcGlobals.players) {
                // Setup
                String operationName = "Setting Up the MPC Parameters (INS_SETUP)";
                System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Reset
                operationName = "Reseting the card to an uninitialized state (INS_RESET)";
                System.out.format(format, operationName, player.Reset(QUORUM_INDEX));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Setup again
                operationName = "Setting Up the MPC Parameters (INS_SETUP)";
                System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                playerIndex++;
            }

            // BUGBUG: Signature without previous EncryptDecrypt will fail on CryptoObjects.KeyPair.Getxi() - as no INS_KEYGEN_xxx was called
            PerformKeyGen(mpcGlobals.players, perfFile);

            //
            // Encrypt / Decrypt
            //
            PerformEncryptDecrypt(BigInteger.TEN, mpcGlobals.players, perfResults, perfFile, runCfg);
            /*
             // Repeated measurements if required
             for (int i = 0; i < runCfg.numSingleOpRepeats; i++) {
             PerformEncryptDecrypt(BigInteger.valueOf(rng.nextInt()), players, channel, perfResults, perfFile);
             }
             */
            //
            // Sign
            //
            PerformSignCache(mpcGlobals.players, perfResults, perfFile);
            PerformSignature(BigInteger.TEN, 1, mpcGlobals.players, perfResults, perfFile, runCfg);
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

            System.out.print("Disconnecting from card...");
            for (MPCPlayer player : mpcGlobals.players) {
                player.disconnect();
            }
            System.out.println(" Done.");

            // Close cvs perf file
            perfFile.close();

            // Save performance results also as latex
            saveLatexPerfLog(perfResults);

            if (runCfg.failedPerfTraps.size() > 0) {
                System.out.println("#########################");
                System.out.println("!!! SOME PERFORMANCE TRAPS NOT REACHED !!!");
                System.out.println("#########################");
                for (String trap : runCfg.failedPerfTraps) {
                    System.out.println(trap);
                }
            } else {
                System.out.println("##########################");
                System.out.println("ALL PERFORMANCE TRAPS REACHED CORRECTLY");
                System.out.println("##########################");
            }

            // Save performance traps into single file
            String perfFileName = String.format("TRAP_RAW_%s.csv", experimentID);
            SavePerformanceResults(runCfg.perfResultsSubpartsRaw, perfFileName);

            // If required, modification of source code files is attempted
            if (MODIFY_SOURCE_FILES_BY_PERF) {
                String dirPath = "..\\!PerfSRC\\Lib\\";
                InsertPerfInfoIntoFiles(dirPath, runCfg.cardName, experimentID, runCfg.perfResultsSubpartsRaw);
            }
        }
    }
    
    public static void TestMPCProtocol_v20170920(MPCRunConfig runCfg) throws FileNotFoundException, Exception {
        String experimentID = String.format("%d", System.currentTimeMillis());
        runCfg.perfFile = new FileOutputStream(String.format("MPC_DETAILPERF_log_%s.csv", experimentID));

        // Prepare globals
        mpcGlobals.Rands = new ECPoint[runCfg.numPlayers];
        mpcGlobals.players.clear();

        // Prepare SecP256r1 curve
        prepareECCurve(mpcGlobals);

        // Obtain list of all connected MPC cards
        System.out.print("Connecting to MPC cards...");
        ArrayList<CardChannel> cardsList = new ArrayList<>();
        CardManagement.ConnectAllPhysicalCards(runCfg.appletAID, cardsList);
        // Create card contexts, fill cards IDs
        short cardID = runCfg.thisCardID;
        for (CardChannel channel : cardsList) {
            CardMPCPlayer cardPlayer = new CardMPCPlayer(channel, format, m_lastTransmitTime, _FAIL_ON_ASSERT, mpcGlobals.curve);
            // If required, make the applet "backdoored" to demonstrate functionality of incorrect behavior of a malicious attacker
            if (_IS_BACKDOORED_EXAMPLE) {
                cardPlayer.SetBackdoorExample(channel, true);
            }
            // Retrieve card information
            cardPlayer.GetCardInfo();
            mpcGlobals.players.add(cardPlayer);
            cardID++;
        }
        System.out.println(" Done.");

        // Simulate all remaining participants in protocol in addition to MPC card(s) 
        for (; cardID < runCfg.numPlayers; cardID++) {
            mpcGlobals.players.add(new SimulatedMPCPlayer(cardID, mpcGlobals.G, mpcGlobals.n, mpcGlobals.curve));
        }

        for (int repeat = 0; repeat < runCfg.numWholeTestRepeats; repeat++) {
            perfResults.clear();
            String logFileName = String.format("MPC_PERF_log_%d.csv", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);

            //
            // Setup card(s)
            //
            short playerIndex = 0;
            for (MPCPlayer player : mpcGlobals.players) {
                // Setup
                String operationName = "Setting Up the MPC Parameters (INS_SETUP)";
                System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Reset
                operationName = "Reseting the card to an uninitialized state (INS_RESET)";
                System.out.format(format, operationName, player.Reset(QUORUM_INDEX));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                // Setup again
                operationName = "Setting Up the MPC Parameters (INS_SETUP)";
                System.out.format(format, operationName, player.Setup(QUORUM_INDEX, runCfg.numPlayers, playerIndex));
                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);

                playerIndex++;
            }

            // BUGBUG: Signature without previous EncryptDecrypt will fail on CryptoObjects.KeyPair.Getxi() - as no INS_KEYGEN_xxx was called
            PerformKeyGen(mpcGlobals.players, perfFile);

            //
            // Encrypt / Decrypt
            //
            PerformEncryptDecrypt(BigInteger.TEN, mpcGlobals.players, perfResults, perfFile, runCfg);
            //
            // Sign
            //
            PerformSignCache(mpcGlobals.players, perfResults, perfFile);
            PerformSignature(BigInteger.TEN, 1, mpcGlobals.players, perfResults, perfFile, runCfg);

            System.out.print("Disconnecting from card...");
            for (MPCPlayer player : mpcGlobals.players) {
                player.disconnect();
            }
            System.out.println(" Done.");

            // Close cvs perf file
            perfFile.close();
        }        
    }

    static void prepareECCurve(MPCGlobals mpcParams) {
        mpcParams.p = new BigInteger(Util.bytesToHex(SecP256r1.p), 16);
        mpcParams.a = new BigInteger(Util.bytesToHex(SecP256r1.a), 16);
        mpcParams.b = new BigInteger(Util.bytesToHex(SecP256r1.b), 16);
        mpcParams.curve = new ECCurve.Fp(mpcParams.p, mpcParams.a, mpcParams.b);
        mpcParams.G = Util.ECPointDeSerialization(mpcGlobals.curve, SecP256r1.G, 0);
        mpcParams.n = new BigInteger(Util.bytesToHex(SecP256r1.r), 16); // also noted as r
        mpcParams.ecSpec = new ECParameterSpec(mpcParams.curve, mpcParams.G, mpcParams.n);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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

    static void PerformKeyGen(ArrayList<MPCPlayer> playersList, FileOutputStream perfFile) throws NoSuchAlgorithmException, Exception {
        Long combinedTime = (long) 0;

        for (MPCPlayer player : mpcGlobals.players) {
            // Generate KeyPair in card
            String operationName = "Generate KeyPair (INS_KEYGEN_INIT)";
            System.out.format(format, operationName, player.GenKeyPair(QUORUM_INDEX));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;

            // Retrieve Hash from card
            operationName = "Retrieve Hash of pub key (INS_KEYGEN_RETRIEVE_HASH)";
            System.out.format(format, operationName, player.RetrievePubKeyHash(QUORUM_INDEX));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }

        // Push hash for all our pub keys
        String operationName = "Store pub key hash (INS_KEYGEN_STORE_HASH)";
        for (MPCPlayer playerTarget : mpcGlobals.players) {
            for (MPCPlayer playerSource : mpcGlobals.players) {
                if (playerTarget != playerSource) {
                    System.out.format(format, operationName, playerTarget.StorePubKeyHash(QUORUM_INDEX, playerSource.GetPlayerIndex(QUORUM_INDEX), playerSource.GetPubKeyHash(QUORUM_INDEX)));
                    writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
                    combinedTime += m_lastTransmitTime;
                }
            }
        }

        // Retrieve card's Public Key
        for (MPCPlayer player : mpcGlobals.players) {
            operationName = "Retrieve Pub Key (INS_KEYGEN_RETRIEVE_PUBKEY)";
            ECPoint pub_share_EC = Util.ECPointDeSerialization(mpcGlobals.curve, player.RetrievePubKey(QUORUM_INDEX), 0);
            System.out.format(format, operationName, Util.bytesToHex(pub_share_EC.getEncoded(false)));
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }
        // Push all public keys
        operationName = "Store Pub Key (INS_KEYGEN_STORE_PUBKEY)";
        for (MPCPlayer playerTarget : mpcGlobals.players) {
            for (MPCPlayer playerSource : mpcGlobals.players) {
                if (playerTarget != playerSource) {
                    System.out.format(format, operationName, playerTarget.StorePubKey(QUORUM_INDEX, playerSource.GetPlayerIndex(QUORUM_INDEX), playerSource.GetPubKey(QUORUM_INDEX).getEncoded(false)));
                    writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
                    combinedTime += m_lastTransmitTime;
                }
            }
        }

        // Retrieve Aggregated Y
        for (MPCPlayer player : mpcGlobals.players) {
            operationName = "Retrieve Aggregated Key (INS_KEYGEN_RETRIEVE_AGG_PUBKEY)";
            System.out.format(format, operationName, player.RetrieveAggPubKey(QUORUM_INDEX));
            if (player instanceof CardMPCPlayer) {
                mpcGlobals.AggPubKey = player.GetAggregatedPubKey(QUORUM_INDEX);
            }
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }

    }

    static void PerformEncryptDecrypt(BigInteger msgToEncDec, ArrayList<MPCPlayer> playersList, ArrayList<Pair<String, Long>> perfResultsList, FileOutputStream perfFile, MPCRunConfig runCfg) throws NoSuchAlgorithmException, Exception {
        String operationName = "";
        Long combinedTime = (long) 0;

        // Encrypt EC Point 
        byte[] ciphertext = null;
        byte[] plaintext = null;
        if (!mpcGlobals.players.isEmpty()) {
            MPCPlayer player = mpcGlobals.players.get(0); // (only first  player == card)
            plaintext = mpcGlobals.G.multiply(msgToEncDec).getEncoded(false);
            operationName = String.format("Encrypt(%s) (INS_ENCRYPT)", msgToEncDec.toString());
            //ciphertext = player.Encrypt(QUORUM_INDEX, plaintext, runCfg, _PROFILE_PERFORMANCE);
            ciphertext = player.Encrypt(QUORUM_INDEX, plaintext);
            writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
            combinedTime += m_lastTransmitTime;
        }

        Long combinedTimeDecrypt = combinedTime - m_lastTransmitTime; // Remove encryption time from combined decryption time
        writePerfLog("* Combined Encrypt time", combinedTime, perfResults, perfFile);

        //
        // Decrypt EC Point
        //
        if (ciphertext.length > 0) {
            ECPoint c2 = Util.ECPointDeSerialization(mpcGlobals.curve, ciphertext, Consts.SHARE_DOUBLE_SIZE_CARRY);

            // Combine all decryption shares (x_ic) (except for card which is added below) 
            ECPoint xc1_EC = mpcGlobals.curve.getInfinity();
            for (MPCPlayer player : mpcGlobals.players) {
                System.out.printf("\n");
                operationName = "Decrypt (INS_DECRYPT)";
                byte[] xc1_share = player.Decrypt(QUORUM_INDEX, ciphertext);
                xc1_EC = xc1_EC.add(Util.ECPointDeSerialization(mpcGlobals.curve, xc1_share, 0).negate()); // combine share from player

                writePerfLog(operationName, m_lastTransmitTime, perfResults, perfFile);
                combinedTime += m_lastTransmitTime;
                combinedTimeDecrypt += m_lastTransmitTime;

                perfResultsList.add(new Pair("* Combined Decrypt time", combinedTimeDecrypt));
                writePerfLog("* Combined Decrypt time", combinedTimeDecrypt, perfResults, perfFile);
            }

            ECPoint plaintext_EC = c2.add(xc1_EC);

            System.out.format(format, "Decryption successful?:",
                    Arrays.equals(plaintext, plaintext_EC.getEncoded(false)));
            if (_FAIL_ON_ASSERT) {
                assert (Arrays.equals(plaintext, plaintext_EC.getEncoded(false)));
            }
        } else {
            System.out.println("ERROR: Failed to retrieve valid encrypted block from card");
            if (_FAIL_ON_ASSERT) {
                assert (false);
            }
        }
    }

    /**
     * Subsequently, the host uses Algorithm 4.3 to compute the aggregate (Rj)
     * of the group elements (Algorithm 4.3) received from the ICs for a
     * particular j, and stores it for future use
     *
     * @param playersList
     * @param channel
     * @param perfResultsList
     * @param perfFile
     * @throws NoSuchAlgorithmException
     * @throws Exception
     */
    static void PerformSignCache(ArrayList<MPCPlayer> playersList, ArrayList<Pair<String, Long>> perfResultsList, FileOutputStream perfFile) throws NoSuchAlgorithmException, Exception {

        Bignat counter = new Bignat((short) 2, false);
        Bignat one = new Bignat((short) 2, false);
        one.one();
        counter.one();

        for (short round = 1; round <= mpcGlobals.Rands.length; round++) {
            boolean bFirstPlayer = true;
            for (MPCPlayer player : playersList) {
                if (bFirstPlayer) {
                    mpcGlobals.Rands[round - 1] = Util.ECPointDeSerialization(mpcGlobals.curve, player.Gen_Rin(QUORUM_INDEX, round), 0);
                    bFirstPlayer = false;
                } else {
                    mpcGlobals.Rands[round - 1] = mpcGlobals.Rands[round - 1].add(Util.ECPointDeSerialization(mpcGlobals.curve, player.Gen_Rin(QUORUM_INDEX, round), 0));
                }
            }
            counter.add(one);
        }
        for (int round = 1; round <= mpcGlobals.Rands.length; round++) {
            System.out.format("Rands[%d]%s\n", round - 1, Util.bytesToHex(mpcGlobals.Rands[round - 1].getEncoded(false)));
        }
        System.out.println();
    }

    /**
     * Host has collected all the shares for the same j, can use Algorithm 4.3
     * on all the σi, j to recover σj , obtaining the aggregate signature (σj ,
     * ϵj ). The recipient of (m, j), σ, ϵ can verify the validity of the
     * signature by checking if ϵ = Hash(R| |Hash(m)| |j), where R = σ ·G +ϵ ·Y.
     *
     * @param msgToSign
     * @param i
     * @param playersList
     * @param channel
     * @param perfResultsList
     * @param perfFile
     * @throws NoSuchAlgorithmException
     * @throws Exception
     */
    static void PerformSignature(BigInteger msgToSign, int counter, ArrayList<MPCPlayer> playersList, ArrayList<Pair<String, Long>> perfResultsList, FileOutputStream perfFile, MPCRunConfig runCfg) throws NoSuchAlgorithmException, Exception {
        // Sign EC Point
        byte[] plaintext_sig = mpcGlobals.G.multiply(msgToSign).getEncoded(false);

        if (!playersList.isEmpty()) {
            BigInteger sum_s_BI = new BigInteger("0");
            BigInteger card_e_BI = new BigInteger("0");
            boolean bFirstPlayer = true;
            for (MPCPlayer player : playersList) {
                if (bFirstPlayer) {
                    sum_s_BI = player.Sign(QUORUM_INDEX, counter, mpcGlobals.Rands[counter - 1].getEncoded(false), plaintext_sig);
                    card_e_BI = player.GetE(QUORUM_INDEX);
                    bFirstPlayer = false;
                } else {
                    sum_s_BI = sum_s_BI.add(player.Sign(QUORUM_INDEX, counter, mpcGlobals.Rands[counter - 1].getEncoded(false), plaintext_sig));
                    sum_s_BI = sum_s_BI.mod(mpcGlobals.n);
                }
            }
            System.out.println(String.format("Sign: %s", Util.bytesToHex(sum_s_BI.toByteArray())));
        }
    }

    private static boolean Verify(byte[] plaintext, ECPoint pubkey, BigInteger s_bi, BigInteger e_bi) throws Exception {

        // Compute rv = sG+eY
        ECPoint rv_EC = mpcGlobals.G.multiply(s_bi); // sG
        rv_EC = rv_EC.add(pubkey.multiply(e_bi)); // +eY

        // Compute ev = H(m||rv)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plaintext);
        md.update(rv_EC.getEncoded(false));
        byte[] ev = md.digest();
        BigInteger ev_bi = new BigInteger(1, ev);
        ev_bi = ev_bi.mod(mpcGlobals.n);

        ///System.out.println(bytesToHex(e_bi.toByteArray()));		
        //System.out.println(bytesToHex(ev_bi.toByteArray()));
        if (_FAIL_ON_ASSERT) {
            assert (e_bi.compareTo(ev_bi) == 0);
        }
        // compare ev with e
        return e_bi.compareTo(ev_bi) == 0;
    }

    // Card Logistics
    private static CardChannel Connect(MPCRunConfig runCfg) throws Exception {
        switch (runCfg.testCardType) {
            case PHYSICAL: {
                return CardManagement.ConnectPhysicalCard(runCfg.targetReaderIndex, runCfg.appletAID);
            }
            case JCOPSIM: {
                return CardManagement.ConnectJCOPSimulator(runCfg.targetReaderIndex, runCfg.appletAID);
            }
            case JCARDSIMLOCAL: {
                return CardManagement.ConnectJCardSimLocalSimulator(runCfg.appletToSimulate, runCfg.appletAID);
            }
            case JCARDSIMREMOTE: {
                return null; // Not implemented yet
            }
            default:
                return null;
        }

    }

    public static byte[] SerializeBigInteger(BigInteger BigInt) {

        int bnlen = BigInt.bitLength() / 8;

        byte[] large_int_b = new byte[bnlen];
        Arrays.fill(large_int_b, (byte) 0);
        int int_len = BigInt.toByteArray().length;
        if (int_len == bnlen) {
            large_int_b = BigInt.toByteArray();
        } else if (int_len > bnlen) {
            large_int_b = Arrays.copyOfRange(BigInt.toByteArray(), int_len
                    - bnlen, int_len);
        } else if (int_len < bnlen) {
            System.arraycopy(BigInt.toByteArray(), 0, large_int_b,
                    large_int_b.length - int_len, int_len);
        }

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
        if (x.toBigInteger().toByteArray().length == (256 / 8)) {
            tempBufferx = x.toBigInteger().toByteArray();
        } else { // 33
            System.arraycopy(x.toBigInteger().toByteArray(), 1, tempBufferx, 0,
                    (256 / 8));
        }

        // src -- This is the source array.
        // srcPos -- This is the starting position in the source array.
        // dest -- This is the destination array.
        // destPos -- This is the starting position in the destination data.
        // length -- This is the number of array elements to be copied.
        byte[] tempBuffery = new byte[256 / 8];
        if (y.toBigInteger().toByteArray().length == (256 / 8)) {
            tempBuffery = y.toBigInteger().toByteArray();
        } else { // 33
            System.arraycopy(y.toBigInteger().toByteArray(), 1, tempBuffery, 0,
                    (256 / 8));
        }

        byte[] O4 = {(byte) 0x04};
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

    private static ECPoint randECPoint() throws Exception {
        ECParameterSpec ecSpec_named = ECNamedCurveTable
                .getParameterSpec("secp256r1"); // NIST P-256
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(ecSpec_named);
        KeyPair apair = kpg.generateKeyPair();
        ECPublicKey apub = (ECPublicKey) apair.getPublic();
        return apub.getQ();
    }

    public static void buildPerfMapping() {
        PERF_STOP_MAPPING.put(PM.PERF_START, "PERF_START");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_1, "TRAP_CRYPTOPS_ENCRYPT_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_2, "TRAP_CRYPTOPS_ENCRYPT_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_3, "TRAP_CRYPTOPS_ENCRYPT_3");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_4, "TRAP_CRYPTOPS_ENCRYPT_4");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_5, "TRAP_CRYPTOPS_ENCRYPT_5");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_6, "TRAP_CRYPTOPS_ENCRYPT_6");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_COMPLETE, "TRAP_CRYPTOPS_ENCRYPT_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_1, "TRAP_CRYPTOPS_DECRYPTSHARE_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_2, "TRAP_CRYPTOPS_DECRYPTSHARE_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE, "TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_1, "TRAP_CRYPTOPS_SIGN_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_2, "TRAP_CRYPTOPS_SIGN_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_3, "TRAP_CRYPTOPS_SIGN_3");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_4, "TRAP_CRYPTOPS_SIGN_4");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_5, "TRAP_CRYPTOPS_SIGN_5");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_6, "TRAP_CRYPTOPS_SIGN_6");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_7, "TRAP_CRYPTOPS_SIGN_7");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_8, "TRAP_CRYPTOPS_SIGN_8");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_9, "TRAP_CRYPTOPS_SIGN_9");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_10, "TRAP_CRYPTOPS_SIGN_10");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_COMPLETE, "TRAP_CRYPTOPS_SIGN_COMPLETE");
    }

    public static String getPerfStopName(short stopID) {
        if (PERF_STOP_MAPPING.containsKey(stopID)) {
            return PERF_STOP_MAPPING.get(stopID);
        } else {
            assert (false);
            return "PERF_UNDEFINED";
        }
    }

    public static short getPerfStopFromName(String stopName) {
        for (Short stopID : PERF_STOP_MAPPING.keySet()) {
            if (PERF_STOP_MAPPING.get(stopID).equalsIgnoreCase(stopName)) {
                return stopID;
            }
        }
        assert (false);
        return PM.TRAP_UNDEFINED;
    }

    /* TODO: move to card where channel is known   
     static long PerfAnalyzeCommand(String operationName, CommandAPDU cmd, CardChannel channel, MPCRunConfig cfg) throws CardException, IOException {
     System.out.println(operationName);
     short prevPerfStop = PM.PERF_START;
     long prevTransmitTime = 0;
     long lastFromPrevTime = 0;
     try {
     for (short perfStop : cfg.perfStops) {
     System.arraycopy(Util.shortToByteArray(perfStop), 0, PERF_COMMAND, ISO7816.OFFSET_CDATA, 2); // set required stop condition
     String operationNamePerf = String.format("%s_%s", operationName, getPerfStopName(perfStop));
     transmit(channel, new CommandAPDU(PERF_COMMAND)); // set performance trap
     ResponseAPDU response = transmit(channel, cmd); // execute target operation
     boolean bFailedToReachTrap = false;
     if (perfStop != cfg.perfStopComplete) { // Check expected error to be equal performance trap
     if (response.getSW() != (perfStop & 0xffff)) {
     // we have not reached expected performance trap
     cfg.failedPerfTraps.add(getPerfStopName(perfStop));
     bFailedToReachTrap = true;
     }
     }
     long fromPrevTime = m_lastTransmitTime - prevTransmitTime;
     if (bFailedToReachTrap) {
     cfg.perfResultsSubparts.add(String.format("[%s-%s], \tfailed to reach after %d ms (0x%x)", getPerfStopName(prevPerfStop), getPerfStopName(perfStop), m_lastTransmitTime, response.getSW()));
     } else {
     cfg.perfResultsSubparts.add(String.format("[%s-%s], \t%d ms", getPerfStopName(prevPerfStop), getPerfStopName(perfStop), fromPrevTime));
     cfg.perfResultsSubpartsRaw.put(perfStop, new Pair(prevPerfStop, fromPrevTime));
     lastFromPrevTime = fromPrevTime;
     }

     prevPerfStop = perfStop;
     prevTransmitTime = m_lastTransmitTime;
     }
     } catch (Exception e) {
     // Print what we have measured so far
     for (String res : cfg.perfResultsSubparts) {
     System.out.println(res);
     }
     throw e;
     }
     // Print measured performance info
     for (String res : cfg.perfResultsSubparts) {
     System.out.println(res);
     }

     return lastFromPrevTime;
     }    
     */
    static void SavePerformanceResults(HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw, String fileName) throws FileNotFoundException, IOException {
        // Save performance traps into single file
        FileOutputStream perfLog = new FileOutputStream(fileName);
        String output = "perfID, previous perfID, time difference between perfID and previous perfID (ms)\n";
        perfLog.write(output.getBytes());
        for (Short perfID : perfResultsSubpartsRaw.keySet()) {
            output = String.format("%d, %d, %d\n", perfID, perfResultsSubpartsRaw.get(perfID).getKey(), perfResultsSubpartsRaw.get(perfID).getValue());
            perfLog.write(output.getBytes());
        }
        perfLog.close();
    }

    static void InsertPerfInfoIntoFiles(String basePath, String cardName, String experimentID, HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw) throws FileNotFoundException, IOException {
        File dir = new File(basePath);
        String[] filesArray = dir.list();
        if ((filesArray != null) && (dir.isDirectory() == true)) {
            // make subdir for results
            String outputDir = String.format("%s\\perf\\%s\\", basePath, experimentID);
            new File(outputDir).mkdirs();

            for (String fileName : filesArray) {
                File dir2 = new File(basePath + fileName);
                if (!dir2.isDirectory()) {
                    InsertPerfInfoIntoFile(String.format("%s\\%s", basePath, fileName), cardName, experimentID, outputDir, perfResultsSubpartsRaw);
                }
            }
        }
    }

    static void InsertPerfInfoIntoFile(String filePath, String cardName, String experimentID, String outputDir, HashMap<Short, Pair<Short, Long>> perfResultsSubpartsRaw) throws FileNotFoundException, IOException {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filePath));
            String basePath = filePath.substring(0, filePath.lastIndexOf("\\"));
            String fileName = filePath.substring(filePath.lastIndexOf("\\"));

            String fileNamePerf = String.format("%s\\%s", outputDir, fileName);
            FileOutputStream fileOut = new FileOutputStream(fileNamePerf);
            String strLine;
            String resLine;
            // For every line of program try to find perfromance trap. If found and perf. is available, then insert comment into code
            while ((strLine = br.readLine()) != null) {

                if (strLine.contains(PERF_TRAP_CALL)) {
                    int trapStart = strLine.indexOf(PERF_TRAP_CALL);
                    int trapEnd = strLine.indexOf(PERF_TRAP_CALL_END);
                    // We have perf. trap, now check if we also corresponding measurement
                    String perfTrapName = (String) strLine.substring(trapStart + PERF_TRAP_CALL.length(), trapEnd);
                    short perfID = getPerfStopFromName(perfTrapName);

                    if (perfResultsSubpartsRaw.containsKey(perfID)) {
                        // We have measurement for this trap, add into comment section
                        resLine = String.format("%s // %d ms (%s,%s) %s", (String) strLine.substring(0, trapEnd + PERF_TRAP_CALL_END.length()), perfResultsSubpartsRaw.get(perfID).getValue(), cardName, experimentID, (String) strLine.subSequence(trapEnd + PERF_TRAP_CALL_END.length(), strLine.length()));
                    } else {
                        resLine = strLine;
                    }
                } else {
                    resLine = strLine;
                }
                resLine += "\n";
                fileOut.write(resLine.getBytes());
            }

            fileOut.close();
        } catch (Exception e) {
            System.out.println(String.format("Failed to transform file %s ", filePath) + e);
        }
    }

}
