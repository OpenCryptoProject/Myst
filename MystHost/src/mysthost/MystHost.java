package mysthost;

import java.io.IOException;
import mystlib.MPCRunConfig;
import mystlib.MystOperations;
import org.apache.commons.cli.*;

/**
 *
 * @author Petr Svenda
 */
public class MystHost {
    private Options opts = new Options();
    private static final String CLI_HEADER = "\nMystHost, a secure multiparty signature and decryption control application.\n\n";
    private static final String CLI_FOOTER = "\nMIT Licensed, 2017\nVasilios Mavroudis, Petr Svenda, OpenCryptoProject";

    public static void main(String[] args) {
        MystHost app = new MystHost();
        app.run(args);
    }

    /**
     * @param args the command line arguments
     */
    private void run(String[] args) {
        try {
            CommandLine cli = parseArgs(args);

            // if help, print and quit
            if (cli.hasOption("help")) {
                help();
                return;
            }

            MystOperations operation = new MystOperations();

            String inputFilePath = cli.getOptionValue("input_file", "input.bin");
            String outputFilePath = cli.getOptionValue("output_file", "output.bin");

            MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
            runCfg.testCardType = MPCRunConfig.CARD_TYPE.PHYSICAL;

            if (cli.hasOption("keygen")) {
                operation.Execute(runCfg, inputFilePath, outputFilePath, MystOperations.CryptoOps.KEYGEN);
            }
            if (cli.hasOption("sign")) {
                operation.Execute(runCfg, inputFilePath, outputFilePath, MystOperations.CryptoOps.SIGN);
            }
            if (cli.hasOption("decrypt")) {
                operation.Execute(runCfg, inputFilePath, outputFilePath, MystOperations.CryptoOps.DECRYPT);
            }
        } catch (MissingArgumentException maex) {
            System.err.println("Option, " + maex.getOption().getOpt() + " requires an argument: " + maex.getOption().getArgName());
        } catch (NumberFormatException nfex) {
            System.err.println("Not a number. " + nfex.getMessage());
        } catch (ParseException /*| IOException*/ ex) {
            System.err.println(ex.getMessage());
        } finally {
        }
    }

    /**
     * Parses command-line options.
     *
     * @param args cli arguments
     * @return parsed CommandLine object
     * @throws ParseException if there are any problems encountered while
     * parsing the command line tokens
     */
    private CommandLine parseArgs(String[] args) throws ParseException {
        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());
        actions.addOption(Option.builder("g").longOpt("keygen").desc("Generate new distributed keypair").build());
        actions.addOption(Option.builder("s").longOpt("sign").desc("Sign data read from input file.").build());
        actions.addOption(Option.builder("d").longOpt("decrypt").desc("Decrypt data read from input file.").build());
        actions.addOption(Option.builder("e").longOpt("encrypt").desc("Encrypt data read from input file.").build());
        opts.addOptionGroup(actions);

        opts.addOption(Option.builder("in").longOpt("inputFile").desc("Input file for operation.").hasArg().argName("input_file").build());
        opts.addOption(Option.builder("out").longOpt("outputFile").desc("Output file for operation.").hasArg().argName("output_file").build());

        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, args);
    }

    /**
     * Prints help.
     */
    private void help() {
        HelpFormatter help = new HelpFormatter();
        help.setOptionComparator(null);
        help.printHelp("MystHost.jar", CLI_HEADER, opts, CLI_FOOTER, true);
    }
}
