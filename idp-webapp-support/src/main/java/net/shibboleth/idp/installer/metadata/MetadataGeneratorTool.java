package net.shibboleth.idp.installer.metadata;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.converters.BaseConverter;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class MetadataGeneratorTool {
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Nonnull
    private final CommandLineArgs args;

    public MetadataGeneratorTool() {
        this.args = new CommandLineArgs();
    }

    /**
     * Set the output file.
     *
     * @param file what to set.
     */
    public void setOutput(File file) {
        this.args.outputFile = file;
    }

    /**
     * Set the encryption Certificate file. Overrides the Spring definition.
     *
     * @param file what to set.
     */
    public void setEncryptionCert(File file) {
        this.args.encryptionCert = file;
    }

    /**
     * Set the signing Certificate file. Overrides the Spring definition.
     *
     * @param file what to set.
     */
    public void setSigningCert(File file) {
        this.args.signingCert = file;
    }

    /**
     * Set the Backchannel Certificate file.
     *
     * @param file what to set.
     */
    public void setBackchannelCert(File file) {
        this.args.backChannelCert = file;
    }

    /**
     * Sets the entityID. Overrides the Spring definition.
     *
     * @param id what to set.
     */
    public void setEntityID(String id) {
        this.args.entityId = id;
    }

    /**
     * Sets the dns name.
     *
     * @param name what to set.
     */
    public void setDnsName(String name) {
        this.args.dnsName = name;
    }

    /**
     * Sets the scope. Overrides the Spring definition.
     *
     * @param value what to set.
     */
    public void setScope(String value) {
        this.args.scope = value;
    }


    public void generate() {
        try {
            final MetadataGeneratorParameters parameters = new MetadataGeneratorParameters();

            if (this.args.encryptionCert != null) {
                parameters.setEncryptionCert(this.args.encryptionCert);
            }
            if (this.args.signingCert != null) {
                parameters.setSigningCert(this.args.signingCert);
            }
            if (this.args.backChannelCert != null) {
                parameters.setBackchannelCert(this.args.backChannelCert);
            }

            final MetadataGenerator generator = new MetadataGenerator(this.args.outputFile);
            final List<List<String>> signing = new ArrayList<>(2);
            List<String> value = parameters.getBackchannelCert();
            if (null != value) {
                signing.add(value);
            }
            value = parameters.getSigningCert();
            if (null != value) {
                signing.add(value);
            }
            generator.setSigningCerts(signing);
            value = parameters.getEncryptionCert();
            if (null != value) {
                generator.setEncryptionCerts(Collections.singletonList(value));
            }
            if (this.args.dnsName != null) {
                generator.setDNSName(this.args.dnsName);
            } else {
                generator.setDNSName(parameters.getDnsName());
            }
            if (this.args.entityId != null) {
                generator.setEntityID(this.args.entityId);
            } else {
                generator.setEntityID(parameters.getEntityID());
            }
            if (this.args.scope != null) {
                generator.setScope(this.args.scope);
            } else {
                generator.setScope(parameters.getScope());
            }
            generator.setSAML2AttributeQueryCommented(true);
            generator.setSAML2LogoutCommented(true);
            generator.generate();

        } catch (final Exception e) {
            log.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private static class CommandLineArgs {
        @Parameter(names = {"--help"}, description = "Display program usage", help = true)
        private boolean help;

        @Parameter(names = {"--signing-cert"}, required = true, converter = FileConverter.class, description = "Signing certificate file")
        @Nonnull
        @NotEmpty
        private File signingCert;

        @Parameter(names = {"--encryption-cert"}, required = true, converter = FileConverter.class, description = "Encryption certificate file")
        @Nonnull
        @NotEmpty
        private File encryptionCert;

        @Parameter(names = {"--backchannel-cert"}, required = true, converter = FileConverter.class, description = "BackChannel certificate file")
        @Nonnull
        @NotEmpty
        private File backChannelCert;

        @Parameter(names = {"--output"}, required = true, converter = FileConverter.class, description = "Output file")
        @Nonnull
        @NotEmpty
        private File outputFile;


        @Parameter(names = {"--entityID"}, required = true, description = "EntityID")
        @Nullable
        private String entityId;


        @Parameter(names = {"--scope"}, required = true, description = "Scope")
        @Nullable
        private String scope;

        @Parameter(names = {"--dnsName"}, required = true, description = "DNS name")
        @Nullable
        private String dnsName;
    }

    public static class FileConverter extends BaseConverter<File> {
        public FileConverter(String optionName) {
            super(optionName);
        }

        public File convert(String value) {
            return new File(value);
        }
    }

    public static void main(String[] args) {
        MetadataGeneratorTool tool = new MetadataGeneratorTool();

        JCommander jc = new JCommander(tool.args, args);
        if (tool.args.help) {
            jc.setProgramName("MetadataGeneratorCommandLine");
            jc.usage();
            return;
        }

        tool.generate();
    }
}
