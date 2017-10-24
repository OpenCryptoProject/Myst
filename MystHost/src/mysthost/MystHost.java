package mysthost;

import java.io.IOException;
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

            if (cli.hasOption("sign")) {
                MystOperation operation = new MystOperation();

                String inputFilePath = cli.getOptionValue("inputFile", "input.bin");
                String outputFilePath = cli.getOptionValue("outnputFile", "input.bin");

                MPCRunConfig runCfg = MPCRunConfig.getDefaultConfig();
                runCfg.testCardType = MPCRunConfig.CARD_TYPE.PHYSICAL;
                runCfg.numPlayers = 4; // TODO: Number of detected cards
                operation.execute(runCfg, inputFilePath, outputFilePath);
            }
        } catch (MissingArgumentException maex) {
            System.err.println("Option, " + maex.getOption().getOpt() + " requires an argument: " + maex.getOption().getArgName());
        } catch (NumberFormatException nfex) {
            System.err.println("Not a number. " + nfex.getMessage());
        } catch (ParseException | IOException ex) {
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
        /*
         * Actions:
         * -st / --setTraps 
         *
         * Options:
         * -bd / --baseDir [base_directory]
         * -mbd / --methodBaseName [name]
         * -tsc / --trapIDStartConst [start_constant] <b> 
         *
         */
        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());
        actions.addOption(Option.builder("st").longOpt("setTraps").desc("Parse input source code files, search for template performance traps and generates both card-side and client-side files for performance profiling.").build());
        opts.addOptionGroup(actions);

        opts.addOption(Option.builder("tsc").longOpt("trapIDStartConst").desc("Initial start value (short) for trapID constants.").hasArg().argName("start_constant").build());
        opts.addOption(Option.builder("bd").longOpt("baseDir").desc("Base directory with template files").hasArg().argName("base_directory").required(true).build());
        opts.addOption(Option.builder("mbd").longOpt("methodBaseName").desc("Base name of method to be profiled.").hasArg().argName("name").required(true).build());

        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, args);
    }

    /**
     * Prints help.
     */
    private void help() {
        HelpFormatter help = new HelpFormatter();
        help.setOptionComparator(null);
        help.printHelp("ECTester.jar", CLI_HEADER, opts, CLI_FOOTER, true);
    }
}
