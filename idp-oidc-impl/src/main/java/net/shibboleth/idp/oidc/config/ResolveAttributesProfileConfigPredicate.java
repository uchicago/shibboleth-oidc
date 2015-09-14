package net.shibboleth.idp.oidc.config;

import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.logic.AbstractRelyingPartyPredicate;
import org.opensaml.profile.context.ProfileRequestContext;

import javax.annotation.Nullable;

/**
 * Action to resolve attributes in the OIDC flow post authentication subflow.
 */
public class ResolveAttributesProfileConfigPredicate extends AbstractRelyingPartyPredicate {
    @Override
    public boolean apply(@Nullable final ProfileRequestContext input) {
        final RelyingPartyContext rpc = getRelyingPartyContextLookupStrategy().apply(input);
        return rpc != null;
    }
}
