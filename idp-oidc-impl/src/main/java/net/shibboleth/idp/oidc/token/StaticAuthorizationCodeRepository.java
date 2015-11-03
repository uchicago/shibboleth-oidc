package net.shibboleth.idp.oidc.token;


import org.joda.time.DateTime;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Repository("staticAuthorizationCodeRepository")
@Primary
public class StaticAuthorizationCodeRepository implements AuthorizationCodeRepository {

    private final Set<AuthorizationCodeEntity> identifiers = new HashSet<>();

    public Set<AuthorizationCodeEntity> getAllAuthorizationCodes() {
        return identifiers;
    }

    @Override
    public AuthorizationCodeEntity save(final AuthorizationCodeEntity authorizationCodeEntity) {
        identifiers.add(authorizationCodeEntity);
        return authorizationCodeEntity;
    }

    @Override
    public AuthorizationCodeEntity getByCode(final String s) {
        for (final AuthorizationCodeEntity identifier : identifiers) {
            if (identifier.getCode().equals(s)) {
                return identifier;
            }
        }
        return null;
    }

    @Override
    public void remove(final AuthorizationCodeEntity authorizationCodeEntity) {
        identifiers.remove(authorizationCodeEntity);
    }

    @Override
    public Collection<AuthorizationCodeEntity> getExpiredCodes() {
        final Set<AuthorizationCodeEntity> expiredIdentifiers = new HashSet<>();

        for (final AuthorizationCodeEntity identifier : identifiers) {
            final DateTime dt = new DateTime(identifier.getExpiration());
            if (dt.isBeforeNow()) {
                expiredIdentifiers.add(identifier);
            }
        }
        return expiredIdentifiers;
    }
}
