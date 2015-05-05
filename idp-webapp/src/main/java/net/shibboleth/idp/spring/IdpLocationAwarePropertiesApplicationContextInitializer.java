package net.shibboleth.idp.spring;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.context.support.ServletContextResource;

import javax.annotation.Nonnull;
import java.util.Properties;

public final class IdpLocationAwarePropertiesApplicationContextInitializer extends IdPPropertiesApplicationContextInitializer {
    private ConfigurableApplicationContext applicationContext;

    @Nonnull
    @Override
    public String[] getSearchLocations() {
        return  new String[] {"idp"};
    }

    @Override
    public void initialize(@Nonnull final ConfigurableApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
        super.initialize(applicationContext);
    }

    @Override
    public void setIdPHomeProperty(@Nonnull final String path, @Nonnull final Properties properties) {
        try {
            final ServletContextResource resource = (ServletContextResource)
                    applicationContext.getResource(getSearchLocations()[0]);
            final String absolutePath = resource.getFile().getAbsolutePath();
            super.setIdPHomeProperty(absolutePath, properties);
        } catch (final Exception e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }
}
