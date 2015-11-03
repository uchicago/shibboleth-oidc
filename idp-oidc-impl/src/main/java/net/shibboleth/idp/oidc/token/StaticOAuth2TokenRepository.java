package net.shibboleth.idp.oidc.token;

import org.joda.time.DateTime;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.mitre.oauth2.repository.OAuth2TokenRepository;
import org.mitre.uma.model.Permission;
import org.mitre.uma.model.ResourceSet;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

@Repository("staticOAuth2TokenRepository")
@Primary
public class StaticOAuth2TokenRepository implements OAuth2TokenRepository {

    private final Set<OAuth2AccessTokenEntity> accessTokenEntities = new HashSet<>();
    private final Set<OAuth2RefreshTokenEntity> refreshTokenEntities = new HashSet<>();

    @Override
    public OAuth2AccessTokenEntity saveAccessToken(final OAuth2AccessTokenEntity oAuth2AccessTokenEntity) {
        accessTokenEntities.add(oAuth2AccessTokenEntity);
        return oAuth2AccessTokenEntity;
    }

    @Override
    public OAuth2RefreshTokenEntity getRefreshTokenByValue(final String s) {
        for (final OAuth2RefreshTokenEntity refreshTokenEntity : refreshTokenEntities) {
            if (refreshTokenEntity.getValue().equals(s)) {
                return refreshTokenEntity;
            }
        }
        return null;
    }

    @Override
    public OAuth2RefreshTokenEntity getRefreshTokenById(final Long aLong) {
        for (final OAuth2RefreshTokenEntity refreshTokenEntity : refreshTokenEntities) {
            if (refreshTokenEntity.getId().equals(aLong)) {
                return refreshTokenEntity;
            }
        }
        return null;
    }

    @Override
    public void clearAccessTokensForRefreshToken(final OAuth2RefreshTokenEntity oAuth2RefreshTokenEntity) {
        final Iterator<OAuth2AccessTokenEntity> it = accessTokenEntities.iterator();
        while (it.hasNext()) {
            final OAuth2AccessTokenEntity accessTokenEntity = it.next();
            if (accessTokenEntity.getRefreshToken().equals(oAuth2RefreshTokenEntity)) {
                it.remove();
            }
        }
    }

    @Override
    public void removeRefreshToken(final OAuth2RefreshTokenEntity oAuth2RefreshTokenEntity) {
        refreshTokenEntities.remove(oAuth2RefreshTokenEntity);
    }

    @Override
    public OAuth2RefreshTokenEntity saveRefreshToken(final OAuth2RefreshTokenEntity oAuth2RefreshTokenEntity) {
        refreshTokenEntities.add(oAuth2RefreshTokenEntity);
        return oAuth2RefreshTokenEntity;
    }

    @Override
    public OAuth2AccessTokenEntity getAccessTokenByValue(final String s) {
        for (final OAuth2AccessTokenEntity accessTokenEntity : accessTokenEntities) {
            if (accessTokenEntity.getValue().equals(s)) {
                return accessTokenEntity;
            }
        }
        return null;
    }

    @Override
    public OAuth2AccessTokenEntity getAccessTokenById(final Long aLong) {
        for (final OAuth2AccessTokenEntity accessTokenEntity : accessTokenEntities) {
            if (accessTokenEntity.getId().equals(aLong)) {
                return accessTokenEntity;
            }
        }
        return null;
    }

    @Override
    public void removeAccessToken(final OAuth2AccessTokenEntity oAuth2AccessTokenEntity) {
        accessTokenEntities.remove(oAuth2AccessTokenEntity);
    }

    @Override
    public void clearTokensForClient(final ClientDetailsEntity clientDetailsEntity) {
        final Iterator<OAuth2AccessTokenEntity> it = accessTokenEntities.iterator();
        while (it.hasNext()) {
            final OAuth2AccessTokenEntity accessTokenEntity = it.next();
            if (accessTokenEntity.getClient().equals(clientDetailsEntity)) {
                it.remove();
            }
        }

        final Iterator<OAuth2RefreshTokenEntity> it2 = refreshTokenEntities.iterator();
        while (it.hasNext()) {
            final OAuth2RefreshTokenEntity refreshTokenEntity = it2.next();
            if (refreshTokenEntity.getClient().equals(clientDetailsEntity)) {
                it.remove();
            }
        }
    }

    @Override
    public List<OAuth2AccessTokenEntity> getAccessTokensForClient(final ClientDetailsEntity clientDetailsEntity) {
        final List<OAuth2AccessTokenEntity> list = new ArrayList<>();
        final Iterator<OAuth2AccessTokenEntity> it = accessTokenEntities.iterator();
        while (it.hasNext()) {
            final OAuth2AccessTokenEntity accessTokenEntity = it.next();
            if (accessTokenEntity.getClient().equals(clientDetailsEntity)) {
                list.add(accessTokenEntity);
            }
        }
        return list;
    }

    @Override
    public List<OAuth2RefreshTokenEntity> getRefreshTokensForClient(final ClientDetailsEntity clientDetailsEntity) {
        final List<OAuth2RefreshTokenEntity> list = new ArrayList<>();
        final Iterator<OAuth2RefreshTokenEntity> it = refreshTokenEntities.iterator();
        while (it.hasNext()) {
            final OAuth2RefreshTokenEntity refreshTokenEntity = it.next();
            if (refreshTokenEntity.getClient().equals(clientDetailsEntity)) {
                list.add(refreshTokenEntity);
            }
        }
        return list;
    }

    @Override
    public OAuth2AccessTokenEntity getAccessTokenForIdToken(final OAuth2AccessTokenEntity oAuth2AccessTokenEntity) {
        for (final OAuth2AccessTokenEntity accessTokenEntity : accessTokenEntities) {
            if (accessTokenEntity.getIdToken().equals(oAuth2AccessTokenEntity)) {
                return accessTokenEntity;
            }
        }
        return null;
    }

    @Override
    public Set<OAuth2AccessTokenEntity> getAllAccessTokens() {
        return accessTokenEntities;
    }

    @Override
    public Set<OAuth2RefreshTokenEntity> getAllRefreshTokens() {
        return refreshTokenEntities;
    }

    @Override
    public Set<OAuth2AccessTokenEntity> getAllExpiredAccessTokens() {
        final Set<OAuth2AccessTokenEntity> expiredTokenEntities = new HashSet<>();
        for (final OAuth2AccessTokenEntity accessTokenEntity : accessTokenEntities) {
            final DateTime expDate = new DateTime(accessTokenEntity.getExpiration());
            if (expDate.isBeforeNow()) {
                expiredTokenEntities.add(accessTokenEntity);
            }
        }
        return expiredTokenEntities;
    }

    @Override
    public Set<OAuth2RefreshTokenEntity> getAllExpiredRefreshTokens() {
        final Set<OAuth2RefreshTokenEntity> expiredTokenEntities = new HashSet<>();
        for (final OAuth2RefreshTokenEntity accessTokenEntity : refreshTokenEntities) {
            final DateTime expDate = new DateTime(accessTokenEntity.getExpiration());
            if (expDate.isBeforeNow()) {
                expiredTokenEntities.add(accessTokenEntity);
            }
        }
        return expiredTokenEntities;
    }

    @Override
    public Set<OAuth2AccessTokenEntity> getAccessTokensForResourceSet(final ResourceSet resourceSet) {
        final Set<OAuth2AccessTokenEntity> tokenEntities = new HashSet<>();
        for (final OAuth2AccessTokenEntity accessTokenEntity : accessTokenEntities) {
            for (final Permission perm : accessTokenEntity.getPermissions()) {
                if (perm.getResourceSet().getId().equals(resourceSet.getId())) {
                    tokenEntities.add(accessTokenEntity);
                }
            }
        }
        return tokenEntities;
    }

    @Override
    public void clearDuplicateAccessTokens() {
        final Iterator<OAuth2AccessTokenEntity> it = accessTokenEntities.iterator();
        while (it.hasNext()) {
            final OAuth2AccessTokenEntity accessTokenEntity = it.next();
            for (final OAuth2AccessTokenEntity entity : accessTokenEntities) {
                if (entity.getJwt().equals(accessTokenEntity.getJwt())) {
                    it.remove();
                    break;
                }
            }
        }

    }

    @Override
    public void clearDuplicateRefreshTokens() {
        final Iterator<OAuth2RefreshTokenEntity> it = refreshTokenEntities.iterator();
        while (it.hasNext()) {
            final OAuth2RefreshTokenEntity refreshTokenEntity = it.next();
            for (final OAuth2RefreshTokenEntity entity : refreshTokenEntities) {
                if (entity.getJwt().equals(refreshTokenEntity.getJwt())) {
                    it.remove();
                    break;
                }
            }
        }
    }
}
