package net.shibboleth.idp.oidc.client;

import org.mitre.openid.connect.model.BlacklistedSite;
import org.mitre.openid.connect.repository.BlacklistedSiteRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Component("staticBlacklistedSiteRepository")
@Primary
public class StaticBlacklistedSiteRepository implements BlacklistedSiteRepository {
    private final Set<BlacklistedSite> identifiers = new HashSet<>();

    @Override
    public Collection<BlacklistedSite> getAll() {
        return identifiers;
    }

    @Override
    public BlacklistedSite getById(final Long aLong) {
        for (final BlacklistedSite identifier : identifiers) {
            if (identifier.getId().equals(aLong)) {
                return identifier;
            }
        }
        return null;
    }

    @Override
    public void remove(final BlacklistedSite blacklistedSite) {
        identifiers.remove(blacklistedSite);
    }

    @Override
    public BlacklistedSite save(final BlacklistedSite blacklistedSite) {
        identifiers.add(blacklistedSite);
        return blacklistedSite;
    }

    @Override
    public BlacklistedSite update(final BlacklistedSite oldBlacklistedSite, final BlacklistedSite blacklistedSite) {
        remove(oldBlacklistedSite);
        save(blacklistedSite);
        return blacklistedSite;
    }
}
