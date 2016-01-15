package net.shibboleth.idp.oidc.config.userinfo;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.SetMultimap;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

@Service("shibbolethClaimTranslator")
@Primary
public class ShibbolethScopeClaimTranslationService implements ScopeClaimTranslationService {
    private final SetMultimap<String, String> scopesToClaims = HashMultimap.create();

    public ShibbolethScopeClaimTranslationService() {
        this.scopesToClaims.put("openid", "sub");
        this.scopesToClaims.put("profile", "name");
        this.scopesToClaims.put("profile", "preferred_username");
        this.scopesToClaims.put("profile", "given_name");
        this.scopesToClaims.put("profile", "family_name");
        this.scopesToClaims.put("profile", "middle_name");
        this.scopesToClaims.put("profile", "nickname");
        this.scopesToClaims.put("profile", "profile");
        this.scopesToClaims.put("profile", "picture");
        this.scopesToClaims.put("profile", "website");
        this.scopesToClaims.put("profile", "gender");
        this.scopesToClaims.put("profile", "zoneinfo");
        this.scopesToClaims.put("profile", "locale");
        this.scopesToClaims.put("profile", "updated_at");
        this.scopesToClaims.put("profile", "birthdate");
        this.scopesToClaims.put("email", "email");
        this.scopesToClaims.put("email", "email_verified");
        this.scopesToClaims.put("phone", "phone_number");
        this.scopesToClaims.put("phone", "phone_number_verified");
        this.scopesToClaims.put("address", "address");
    }

    public Set<String> getClaimsForScope(final String scope) {
        return (Set)(this.scopesToClaims.containsKey(scope)?this.scopesToClaims.get(scope):new HashSet());
    }

    public Set<String> getClaimsForScopeSet(final Set<String> scopes) {
        final HashSet result = new HashSet();
        final Iterator it = scopes.iterator();

        while(it.hasNext()) {
            final String scope = (String)it.next();
            result.addAll(this.getClaimsForScope(scope));
        }

        return result;
    }
}
