package net.shibboleth.idp.oidc.client;

import org.mitre.openid.connect.model.ApprovedSite;
import org.mitre.openid.connect.repository.ApprovedSiteRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Component("staticApprovedSiteRepository")
@Primary
public class StaticApprovedSiteRepository implements ApprovedSiteRepository {
    private final Set<ApprovedSite> identifiers = new HashSet<>();

    @Override
    public ApprovedSite getById(final Long aLong) {
        for (final ApprovedSite identifier : identifiers) {
            if (identifier.getId().equals(aLong)) {
                return identifier;
            }
        }
        return null;
    }

    @Override
    public Collection<ApprovedSite> getAll() {
        return identifiers;
    }

    @Override
    public Collection<ApprovedSite> getByClientIdAndUserId(final String clientId, final String userid) {
        final Set<ApprovedSite> collection = new HashSet<>();
        for (final ApprovedSite identifier : identifiers) {
            if (identifier.getClientId().equals(clientId) && identifier.getUserId().equals(userid)) {
                collection.add(identifier);
            }
        }
        return collection;

    }

    @Override
    public void remove(final ApprovedSite approvedSite) {
        identifiers.remove(approvedSite);
    }

    @Override
    public ApprovedSite save(final ApprovedSite approvedSite) {
        identifiers.add(approvedSite);
        return approvedSite;
    }

    @Override
    public Collection<ApprovedSite> getByUserId(final String s) {
        final Set<ApprovedSite> collection = new HashSet<>();
        for (final ApprovedSite identifier : identifiers) {
            if (identifier.getUserId().equals(s)) {
                collection.add(identifier);
            }
        }
        return collection;
    }

    @Override
    public Collection<ApprovedSite> getByClientId(final String s) {
        final Set<ApprovedSite> collection = new HashSet<>();
        for (final ApprovedSite identifier : identifiers) {
            if (identifier.getClientId().equals(s)) {
                collection.add(identifier);
            }
        }
        return collection;
    }
}
