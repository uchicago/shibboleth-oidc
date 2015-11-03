package net.shibboleth.idp.oidc.client;

import org.mitre.openid.connect.model.WhitelistedSite;
import org.mitre.openid.connect.repository.WhitelistedSiteRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Component("staticWhitelistedSiteRepository")
@Primary
public class StaticWhitelistedSiteRepository implements WhitelistedSiteRepository {
    private final Set<WhitelistedSite> identifiers = new HashSet<>();

    @Override
    public Collection<WhitelistedSite> getAll() {
        return identifiers;
    }

    @Override
    public WhitelistedSite getById(final Long aLong) {
        for (final WhitelistedSite identifier : identifiers) {
            if (identifier.getId().equals(aLong)) {
                return identifier;
            }
        }
        return null;
    }

    @Override
    public WhitelistedSite getByClientId(final String s) {
        for (final WhitelistedSite identifier : identifiers) {
            if (identifier.getClientId().equals(s)) {
                return identifier;
            }
        }
        return null;
    }

    @Override
    public Collection<WhitelistedSite> getByCreator(final String s) {
        final Set<WhitelistedSite> collection = new HashSet<>();
        for (final WhitelistedSite identifier : identifiers) {
            if (identifier.getCreatorUserId().equals(s)) {
                collection.add(identifier);
            }
        }
        return collection;
    }

    @Override
    public void remove(final WhitelistedSite whitelistedSite) {
        identifiers.remove(whitelistedSite);
    }

    @Override
    public WhitelistedSite save(final WhitelistedSite whitelistedSite) {
        identifiers.add(whitelistedSite);
        return whitelistedSite;
    }

    @Override
    public WhitelistedSite update(final WhitelistedSite oldWhitelistedSite, final WhitelistedSite whitelistedSite) {
        remove(oldWhitelistedSite);
        save(whitelistedSite);
        return whitelistedSite;
    }
}
