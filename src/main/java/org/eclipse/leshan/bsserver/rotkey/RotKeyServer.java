package org.eclipse.leshan.bsserver.rotkey;

import java.util.ArrayList;
import java.util.List;


import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.eclipse.leshan.core.SecurityMode;
import org.eclipse.leshan.core.request.BindingMode;
import org.eclipse.leshan.core.request.Identity;
import org.eclipse.leshan.core.util.Hex;
import org.eclipse.leshan.server.bootstrap.BootstrapConfig;
import org.eclipse.leshan.server.bootstrap.BootstrapConfigStore;
import org.eclipse.leshan.server.bootstrap.BootstrapSession;
import org.eclipse.leshan.server.bootstrap.ConfigurationChecker;
import org.eclipse.leshan.server.bootstrap.InvalidConfigurationException;
import org.eclipse.leshan.server.californium.bootstrap.LeshanBootstrapServer;
import org.eclipse.leshan.server.californium.bootstrap.LeshanBootstrapServerBuilder;
import org.eclipse.leshan.server.security.BootstrapSecurityStore;
import org.eclipse.leshan.server.security.SecurityInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RotKeyServer {

    private static final Logger LOG = LoggerFactory.getLogger(RotKeyServer.class);

    private static final String USAGE = "java -jar leshan-bsserver-rotkey.jar [OPTION]";

    public static void main(String[] args) {
        Options options = new Options();

        LeshanBootstrapServerBuilder builder = new LeshanBootstrapServerBuilder();

        options.addOption("h", "help", false, "Display help information.");
        options.addOption("slh", "coapshost", true, "Set the secure local CoAP address.\nDefault: any local address.");
        options.addOption("slp", "coapsport", true, "Set the secure local CoAP port.\nDefault: 5684.");
        options.addOption("e", "endpoint", true, "Set device endpoint name.\nDefault: myDevice.");

        HelpFormatter formatter = new HelpFormatter();
        formatter.setWidth(120);
        formatter.setOptionComparator(null);

        // Parse arguments
        CommandLine cl;
        try {
            cl = new DefaultParser().parse(options, args);
        } catch (ParseException e) {
            System.err.println("Parsing failed.  Reason: " + e.getMessage());
            formatter.printHelp(USAGE, options);
            return;
        }

        // Print help
        if (cl.hasOption("help")) {
            formatter.printHelp(USAGE, options);
            return;
        }

        // Abort if unexpected options
        if (cl.getArgs().length > 0) {
            System.err.println("Unexpected option or arguments : " + cl.getArgList());
            formatter.printHelp(USAGE, options);
            return;
        }

        // Define Bootstrap server URL
        String secureLocalAddress = cl.hasOption("slh") ? cl.getOptionValue("slh") : "localhost";
        String secureLocalPortOption = cl.getOptionValue("slp");
        Integer secureLocalPort = null;
        if (secureLocalPortOption != null) {
            secureLocalPort = Integer.parseInt(secureLocalPortOption);
        }
        if (secureLocalPort == null) {
            secureLocalPort = 5684;
        }
        builder.setLocalSecureAddress(null, secureLocalPort);

        final String bootstrapURL = String.format("coaps://%s:%d", secureLocalAddress, secureLocalPort);
        LOG.info("BS Server URL: {}", bootstrapURL);

        // Define device endpoint name
        // (we support only 1 device in this example)
        final String deviceEndpointName = cl.hasOption("endpoint") ? cl.getOptionValue("endpoint") : "myDevice";
        LOG.info("Endpoint name: {}", deviceEndpointName);

        // Define a list of credentials.
        final List<SecurityInfo> credentials = new ArrayList<>();
        credentials.add(
                SecurityInfo.newPreSharedKeyInfo(deviceEndpointName, "identity1", Hex.decodeHex("AAAA".toCharArray())));
        credentials.add(
                SecurityInfo.newPreSharedKeyInfo(deviceEndpointName, "identity2", Hex.decodeHex("BBBB".toCharArray())));
        credentials.add(
                SecurityInfo.newPreSharedKeyInfo(deviceEndpointName, "identity3", Hex.decodeHex("CCCC".toCharArray())));
        credentials.add(
                SecurityInfo.newPreSharedKeyInfo(deviceEndpointName, "identity4", Hex.decodeHex("DDDD".toCharArray())));

        // Create a security store which accept all credentials above for our
        // device.
        // SecurityStore contains information needed to established DTLS
        // connection on bootstrap server
        builder.setSecurityStore(new BootstrapSecurityStore() {

            public SecurityInfo getByIdentity(String receivedPskIdentity) {
                for (SecurityInfo cred : credentials) {
                    if (cred.usePSK()) {
                        if (receivedPskIdentity.equals(cred.getIdentity())) {
                            LOG.info("Device try to connect using '{}' identity. (PSK expected '{}')",
                                    cred.getIdentity(), Hex.encodeHexString(cred.getPreSharedKey()).toUpperCase());
                            return cred;
                        }
                    }
                }
                LOG.info("Device try to connect with unknown identity {}", receivedPskIdentity);
                return null;
            }

            public List<SecurityInfo> getAllByEndpoint(String receivedEndpoint) {
                return credentials;
            }
        });

        // Create a bootstrap config store.
        // This store contains the bootstrap configuration to write on device.
        builder.setConfigStore(new BootstrapConfigStore() {

            ConfigurationChecker checker = new ConfigurationChecker();
            private int keyIndex = 0; // index used to rotate keys

            public BootstrapConfig get(String endpoint, Identity deviceIdentity, BootstrapSession session) {
                // Rotate keys.
                keyIndex = (keyIndex + 1) % credentials.size();

                // Get next credentials.
                SecurityInfo bsCredential = credentials.get(keyIndex);
                LOG.info("Try to apply new credentials '{}','{}'", bsCredential.getIdentity(),
                        Hex.encodeHexString(bsCredential.getPreSharedKey()).toUpperCase());
                BootstrapConfig config = new BootstrapConfig();

                // Path to delete.
                config.toDelete.add("/");

                // Configuration for LWM2M bootstrap server.
                BootstrapConfig.ServerSecurity bsSecurity = new BootstrapConfig.ServerSecurity();
                bsSecurity.bootstrapServer = true;
                bsSecurity.publicKeyOrId = bsCredential.getIdentity().getBytes();
                bsSecurity.secretKey = bsCredential.getPreSharedKey();
                bsSecurity.securityMode = SecurityMode.PSK;
                bsSecurity.uri = bootstrapURL;
                bsSecurity.serverId = 0;
                bsSecurity.bootstrapServerAccountTimeout = null;
                config.security.put(0, bsSecurity);

                // Configuration for LWM2M server.
                BootstrapConfig.ServerSecurity dmSecurity = new BootstrapConfig.ServerSecurity();
                dmSecurity.bootstrapServer = false;
                // PSK Identity for LWM2M server
                dmSecurity.publicKeyOrId = "invalidIdentityToForceRebootstrap".getBytes();
                // PSK Key for LWM2M server
                dmSecurity.secretKey = Hex.decodeHex("1234567890".toCharArray());
                dmSecurity.securityMode = SecurityMode.PSK;
                // use Leshan Sandbox as LWM2M server
                dmSecurity.uri = "coaps://leshan.eclipseprojects.io:5784";
                dmSecurity.serverId = 123;
                config.security.put(1, dmSecurity);
                BootstrapConfig.ServerConfig dmServer = new BootstrapConfig.ServerConfig();
                dmServer.binding = BindingMode.U; // or BindingMode.UQ
                dmServer.shortId = 123;
                dmServer.lifetime = 300; // 5min
                config.servers.put(0, dmServer);


                try {
                    checker.verify(config);
                } catch (InvalidConfigurationException e) {
                    LOG.info("Invalid bootstrap config. {}",config, e);
                    return null;
                }
                return config;
            }
        });

        LeshanBootstrapServer server = builder.build();
        server.start();
    }
}
