package net.shibboleth.idp.oidc.token;

import org.mitre.openid.connect.model.PairwiseIdentifier;
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Repository;

import java.util.HashSet;
import java.util.Set;

@Repository("staticPairwiseIdentifierRepository")
@Primary
public class StaticPairwiseIdentifierRepository implements PairwiseIdentifierRepository {

    private final Set<PairwiseIdentifier> identifiers = new HashSet<>();

    @Override
    public PairwiseIdentifier getBySectorIdentifier(final String sub, final String sectorIdentifierUri) {
        for (final PairwiseIdentifier identifier : identifiers) {
            if (identifier.getUserSub().equals(sub) && identifier.getIdentifier().equals(sectorIdentifierUri)) {
                return identifier;
            }
        }
        return null;
    }

    @Override
    public void save(final PairwiseIdentifier pairwiseIdentifier) {
        identifiers.add(pairwiseIdentifier);
    }
}
