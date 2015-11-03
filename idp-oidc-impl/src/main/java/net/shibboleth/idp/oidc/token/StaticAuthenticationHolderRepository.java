package net.shibboleth.idp.oidc.token;

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.AuthorizationCodeEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.mitre.oauth2.repository.OAuth2TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Repository("staticAuthenticationHolderRepository")
@Primary
public class StaticAuthenticationHolderRepository implements AuthenticationHolderRepository {

    private final List<AuthenticationHolderEntity> authenticationHolderEntities = new ArrayList<>();

    @Autowired
    private OAuth2TokenRepository oAuth2TokenRepository;

    @Autowired
    private StaticAuthorizationCodeRepository authorizationCodeRepository;

    @Override
    public List<AuthenticationHolderEntity> getAll() {
        return authenticationHolderEntities;
    }

    @Override
    public AuthenticationHolderEntity getById(final Long aLong) {
        for (final AuthenticationHolderEntity identifier : authenticationHolderEntities) {
            if (identifier.getId().equals(aLong)) {
                return identifier;
            }
        }
        return null;
    }

    @Override
    public void remove(final AuthenticationHolderEntity authenticationHolderEntity) {
        authenticationHolderEntities.remove(authenticationHolderEntity);
    }

    @Override
    public AuthenticationHolderEntity save(final AuthenticationHolderEntity authenticationHolderEntity) {
        authenticationHolderEntities.add(authenticationHolderEntity);
        return authenticationHolderEntity;
    }

    @Override
    public List<AuthenticationHolderEntity> getOrphanedAuthenticationHolders() {
        final List<AuthenticationHolderEntity> list = new ArrayList<>();

        final Set<OAuth2AccessTokenEntity> accessTokens = oAuth2TokenRepository.getAllAccessTokens();
        final Set<OAuth2RefreshTokenEntity> refreshTokens = oAuth2TokenRepository.getAllRefreshTokens();
        final Set<AuthorizationCodeEntity> authzTokens = authorizationCodeRepository.getAllAuthorizationCodes();

        for (final AuthenticationHolderEntity identifier : authenticationHolderEntities) {
            boolean found = false;
            for (final OAuth2AccessTokenEntity accessToken : accessTokens) {
                if (accessToken.getAuthenticationHolder().getId().equals(identifier.getId())) {
                    found = true;
                    break;
                }
            }
            if (found) {
                continue;
            }

            for (final OAuth2RefreshTokenEntity refreshToken : refreshTokens) {
                if (refreshToken.getAuthenticationHolder().getId().equals(identifier.getId())) {
                    found = true;
                    break;
                }
            }
            if (found) {
                continue;
            }

            for (final AuthorizationCodeEntity authzToken : authzTokens) {
                if (authzToken.getAuthenticationHolder().getId().equals(identifier.getId())) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                list.add(identifier);
            }
        }
        return list;
    }
}
