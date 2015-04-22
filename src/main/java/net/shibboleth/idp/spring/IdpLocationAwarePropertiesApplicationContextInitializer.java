package net.shibboleth.idp.spring;

import javax.annotation.Nonnull;

public class IdpLocationAwarePropertiesApplicationContextInitializer extends IdPPropertiesApplicationContextInitializer {
    @Nonnull
    @Override
    public String[] getSearchLocations() {
        return  new String[] {"classpath:",};

    }
}
