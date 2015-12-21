package net.shibboleth.idp.oidc.token;


import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.util.MinimalPrettyPrinter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.joda.time.DateTime;
import org.joda.time.Seconds;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;
import org.opensaml.storage.StorageSerializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Collections;
import java.util.Set;

@Component("abstractOAuth2TokenRepository")
public abstract class AbstractOAuth2TokenRepository {

    @Autowired
    @Qualifier("openidConnectStorageService")
    private OpenIdConnectStorageService storageService;

    protected String getOAuth2AccessTokenStorageContext() {
        return OAuth2AccessToken.class.getCanonicalName();
    }

    protected String getOAuth2RefreshTokenStorageContext() {
        return ExpiringOAuth2RefreshToken.class.getCanonicalName();
    }

    public void storeOAuth2AccessToken(final OAuth2AccessTokenEntity t) {
        try {
            final String context = getOAuth2AccessTokenStorageContext();
            final DateTime dt = new DateTime(t.getExpiration());
            final long exp = Seconds.secondsBetween(DateTime.now(), dt).toPeriod().getMillis();

            if (!this.storageService.create(context, t.getValue(), t,
                    new OAuth2TokenStorageSerializer(OAuth2AccessToken.class),
                    exp)) {
                throw new RuntimeException("Failed to store token " + t);
            }
        } catch (final IOException e) {
            throw new RuntimeException("Failed to store token " + t, e);
        }
    }

    public void storeOAuth2RefreshToken(final OAuth2RefreshTokenEntity t) {
        try {
            final String context = getOAuth2RefreshTokenStorageContext();
            final DateTime dt = new DateTime(t.getExpiration());
            final long exp = Seconds.secondsBetween(DateTime.now(), dt).toPeriod().getMillis();

            if (!this.storageService.create(context, t.getValue(), t,
                    new OAuth2TokenStorageSerializer(OAuth2RefreshTokenEntity.class),
                    exp)) {
                throw new RuntimeException("Failed to store token " + t);
            }
        } catch (final IOException e) {
            throw new RuntimeException("Failed to store token " + t, e);
        }
    }

    public void deleteOAuth2RefreshToken(final OAuth2RefreshTokenEntity t) {
        try {
            final String context = getOAuth2RefreshTokenStorageContext();
            if (!this.storageService.delete(context, t.getValue())) {
                throw new RuntimeException("Failed to delete token " + t);
            }
        } catch (final IOException e) {
            throw new RuntimeException("Failed to delete token " + t, e);
        }
    }

    public void deleteOAuth2AccessToken(final OAuth2AccessTokenEntity t) {
        try {
            final String context = getOAuth2AccessTokenStorageContext();
            if (!this.storageService.delete(context, t.getValue())) {
                throw new RuntimeException("Failed to delete token " + t);
            }
        } catch (final IOException e) {
            throw new RuntimeException("Failed to delete token " + t, e);
        }
    }

    public Set<OAuth2AccessTokenEntity> getAllAccessTokens() {
        try {
            return Collections.emptySet();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Set<OAuth2RefreshTokenEntity> getAllRefreshTokens() {
        try {
            return Collections.emptySet();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static class OAuth2TokenStorageSerializer<T> implements StorageSerializer<T> {
        private ObjectMapper objectMapper;
        private final Class<T> objectType;

        public OAuth2TokenStorageSerializer(final Class<T> objectType) {
            this.objectType = objectType;
        }

        @Nonnull
        @Override
        public String serialize(@Nonnull final Object o) throws IOException {
            try {
                final StringWriter out = new StringWriter();
                this.objectMapper.writer(new MinimalPrettyPrinter()).writeValue(out, o);
                return out.toString();
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Nonnull
        @Override
        public T deserialize(final long l, @Nonnull @NotEmpty final String s, @Nonnull @NotEmpty final String s1,
                                  @Nonnull @NotEmpty final String s2, @Nullable final Long aLong) throws IOException {
            try {
                return this.objectMapper.readValue(s, this.objectType);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public boolean isInitialized() {
            return this.objectMapper != null;
        }

        @Override
        public void initialize() throws ComponentInitializationException {
            this.objectMapper = initializeObjectMapper();
        }

        private static ObjectMapper initializeObjectMapper() {
            final ObjectMapper mapper = new ObjectMapper();
            mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
            mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
            mapper.setVisibility(PropertyAccessor.SETTER, JsonAutoDetect.Visibility.PROTECTED_AND_PUBLIC);
            mapper.setVisibility(PropertyAccessor.GETTER, JsonAutoDetect.Visibility.PROTECTED_AND_PUBLIC);
            mapper.setVisibility(PropertyAccessor.IS_GETTER, JsonAutoDetect.Visibility.PROTECTED_AND_PUBLIC);
            mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);
            return mapper;
        }

    }
}
