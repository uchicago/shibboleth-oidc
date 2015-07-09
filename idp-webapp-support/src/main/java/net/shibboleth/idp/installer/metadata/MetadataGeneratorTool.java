/*
 *  Licensed to the University Corporation for Advanced Internet Development,
 *  Inc. (UCAID) under one or more contributor license agreements.  See the
 *  NOTICE file distributed with this work for additional information regarding
 *  copyright ownership. The UCAID licenses this file to You under the Apache
 *  License, Version 2.0 (the "License"); you may not use this file except in
 *  compliance with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

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


/**
 * Generates metadata for the idp, typically as part of the installation
 * process and build. It is intended to be invoked from the command line.
 */
public final class MetadataGeneratorTool {
    /**
     * The Logger instance.
     */
    private final Logger log = LoggerFactory.getLogger(getClass());

    /**
     * The command-line arguments.
     */
    @Nonnull
    private final CommandLineArgs args;

    /**
     * Instantiates a new instance. Initializes the command line args.
     */
    public MetadataGeneratorTool() {
        this.args = new CommandLineArgs();
    }

    /**
     * Set the output file.
     *
     * @param file metadata file's destination
     */
    public void setOutput(final File file) {
        this.args.outputFile = file;
    }

    /**
     * Set the encryption Certificate file. Overrides the Spring definition.
     *
     * @param file the certificate file
     */
    public void setEncryptionCert(final File file) {
        this.args.encryptionCert = file;
    }

    /**
     * Set the signing Certificate file. Overrides the Spring definition.
     *
     * @param file the signing certificate
     */
    public void setSigningCert(final File file) {
        this.args.signingCert = file;
    }

    /**
     * Set the Backchannel Certificate file.
     *
     * @param file back-channel cert
     */
    public void setBackchannelCert(final File file) {
        this.args.backChannelCert = file;
    }

    /**
     * Sets the entityID.
     *
     * @param id entityid for this metadata.
     */
    public void setEntityID(final String id) {
        this.args.entityId = id;
    }

    /**
     * Sets the dns name.
     *
     * @param name dns name
     */
    public void setDnsName(final String name) {
        this.args.dnsName = name;
    }

    /**
     * Sets the scope.
     *
     * @param value scope value for the metadata
     */
    public void setScope(final String value) {
        this.args.scope = value;
    }


    /**
     * Generate void.
     */
    public void generate() {
        try {
            final MetadataGeneratorParameters parameters = buildMetadataGeneratorParameters();

            final MetadataGenerator generator = new MetadataGenerator(args.outputFile);
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
            if (args.dnsName != null) {
                generator.setDNSName(args.dnsName);
            } else {
                generator.setDNSName(parameters.getDnsName());
            }
            if (args.entityId != null) {
                generator.setEntityID(args.entityId);
            } else {
                generator.setEntityID(parameters.getEntityID());
            }
            if (args.scope != null) {
                generator.setScope(args.scope);
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

    /**
     * Build metadata generator parameters by passing the encryption,
     * signing and back-channel certs to the parameter generator.
     *
     * @return the metadata generator parameters
     */
    private MetadataGeneratorParameters buildMetadataGeneratorParameters() {
        final MetadataGeneratorParameters parameters = new MetadataGeneratorParameters();

        if (args.encryptionCert != null) {
            parameters.setEncryptionCert(args.encryptionCert);
        }
        if (args.signingCert != null) {
            parameters.setSigningCert(args.signingCert);
        }
        if (args.backChannelCert != null) {
            parameters.setBackchannelCert(args.backChannelCert);
        }
        return parameters;
    }

    /**
     * The type Command line args.
     */
    private static class CommandLineArgs {
        /**
         * The Help.
         */
        @Parameter(names = {"--help"}, description = "Display program usage", help = true)
        private boolean help;

        /**
         * The Signing cert.
         */
        @Parameter(names = {"--signing-cert"}, required = true,
                converter = FileConverter.class, description = "Signing certificate file")
        @Nonnull
        @NotEmpty
        private File signingCert;

        /**
         * The Encryption cert.
         */
        @Parameter(names = {"--encryption-cert"}, required = true,
                converter = FileConverter.class, description = "Encryption certificate file")
        @Nonnull
        @NotEmpty
        private File encryptionCert;

        /**
         * The Back channel cert.
         */
        @Parameter(names = {"--backchannel-cert"}, required = true,
                converter = FileConverter.class, description = "BackChannel certificate file")
        @Nonnull
        @NotEmpty
        private File backChannelCert;

        /**
         * The Output file.
         */
        @Parameter(names = {"--output"}, required = true,
                converter = FileConverter.class, description = "Output file")
        @Nonnull
        @NotEmpty
        private File outputFile;


        /**
         * The Entity id.
         */
        @Parameter(names = {"--entityID"}, required = true, description = "EntityID")
        @Nullable
        private String entityId;


        /**
         * The Scope.
         */
        @Parameter(names = {"--scope"}, required = true, description = "Scope")
        @Nullable
        private String scope;

        /**
         * The Dns name.
         */
        @Parameter(names = {"--dnsName"}, required = true, description = "DNS name")
        @Nullable
        private String dnsName;
    }

    /**
     * The type File converter.
     */
    public static class FileConverter extends BaseConverter<File> {
        /**
         * Instantiates a new File converter.
         *
         * @param optionName the option name
         */
        public FileConverter(final String optionName) {
            super(optionName);
        }

        @Override
        public File convert(final String value) {
            return new File(value);
        }
    }

    /**
     * Main void.
     *
     * @param args the args
     */
    public static void main(final String[] args) {
        final MetadataGeneratorTool tool = new MetadataGeneratorTool();

        final JCommander jc = new JCommander(tool.args, args);
        if (tool.args.help) {
            jc.setProgramName("MetadataGeneratorCommandLine");
            jc.usage();
            return;
        }

        tool.generate();
    }
}
