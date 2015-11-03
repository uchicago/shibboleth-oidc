package net.shibboleth.idp.oidc.config;

import com.google.common.base.Function;
import javax.annotation.Nullable;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import org.opensaml.profile.context.ProfileRequestContext;

/**
 * Looks up the {@link RelyingPartyContext}
 * and makes sure the config class provided is an instance
 * of the profile configuration provided by that context.
 * @param <T>  the type parameter
 */
public class ConfigLookupFunction<T> implements Function<ProfileRequestContext, T> {
    private final Class<T> configClass;

    /**
     * Instantiates a Config lookup function.
     *
     * @param clazz the clazz
     */
    public ConfigLookupFunction(final Class<T> clazz) {
        this.configClass = clazz;
    }

    @Nullable
    @Override
    public T apply(@Nullable final ProfileRequestContext profileRequestContext) {
        if(profileRequestContext != null) {
            final RelyingPartyContext rpContext = profileRequestContext.getSubcontext(RelyingPartyContext.class, false);
            if(rpContext != null && this.configClass.isInstance(rpContext.getProfileConfig())) {
                return this.configClass.cast(rpContext.getProfileConfig());
            }
        }

        return null;
    }
}
