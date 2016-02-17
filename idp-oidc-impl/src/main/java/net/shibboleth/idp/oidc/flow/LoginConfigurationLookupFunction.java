package net.shibboleth.idp.oidc.flow;

import com.google.common.base.Function;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

/**
 * Looks up the {@link RelyingPartyContext}
 * and makes sure the config class provided is an instance
 * of the profile configuration provided by that context.
 *
 * @param <T> the type parameter
 */
public class LoginConfigurationLookupFunction<T> implements Function<ProfileRequestContext, T> {
    private final Logger log = LoggerFactory.getLogger(BuildAuthenticationContextAction.class);

    private final Class<T> configClass;

    /**
     * Instantiates a Config lookup function.
     *
     * @param clazz the clazz
     */
    public LoginConfigurationLookupFunction(final Class<T> clazz) {
        this.configClass = clazz;
    }

    @Nullable
    @Override
    public T apply(@Nullable final ProfileRequestContext profileRequestContext) {
        if (profileRequestContext == null) {
            log.error("Profile request context is null");
            return null;
        }

        final RelyingPartyContext rpContext = profileRequestContext.getSubcontext(RelyingPartyContext.class, false);
        if (rpContext == null) {
            log.error("There is no relying party context defined");
            return null;
        }

        log.debug("Located relying party context with id {}", rpContext.getRelyingPartyId());

        if (!this.configClass.isInstance(rpContext.getProfileConfig())) {
            log.error("{} cannot be applied or is not an instance of the relying party context profile configuration");
            return null;
        }
        return this.configClass.cast(rpContext.getProfileConfig());
    }
}
