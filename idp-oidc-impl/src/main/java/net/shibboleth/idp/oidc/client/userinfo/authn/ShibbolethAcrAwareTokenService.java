/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements. See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.shibboleth.idp.oidc.client.userinfo.authn;


import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import net.shibboleth.idp.oidc.config.OIDCConstants;
import org.mitre.jwt.encryption.service.JWTEncryptionAndDecryptionService;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService;
import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.request.ConnectRequestParameters;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.mitre.openid.connect.util.IdTokenHashUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * The type Shibboleth acr aware token service.
 */
@Primary
@Component("shibbolethAcrAwareTokenService")
public class ShibbolethAcrAwareTokenService implements OIDCTokenService {
    /**
     * The Log.
     */
    private final Logger log = LoggerFactory.getLogger(ShibbolethAcrAwareTokenService.class);

    /**
     * The Jwt service.
     */
    @Autowired
    private JWTSigningAndValidationService jwtService;

    /**
     * The Authentication holder repository.
     */
    @Autowired
    private AuthenticationHolderRepository authenticationHolderRepository;

    /**
     * The Config bean.
     */
    @Autowired
    private ConfigurationPropertiesBean configBean;

    /**
     * The Encrypters.
     */
    @Autowired
    private ClientKeyCacheService encrypters;

    /**
     * The Symmetric cache service.
     */
    @Autowired
    private SymmetricKeyJWTValidatorCacheService symmetricCacheService;

    /**
     * The Token service.
     */
    @Autowired
    private OAuth2TokenEntityService tokenService;

    @Override
    public JWT createIdToken(final ClientDetailsEntity client, final OAuth2Request request,
                             final Date issueTime, final String sub,
                             final OAuth2AccessTokenEntity accessToken) {

        JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();

        if (client.getIdTokenSignedResponseAlg() != null) {
            signingAlg = client.getIdTokenSignedResponseAlg();
        }

        final JWTClaimsSet.Builder idClaims = new JWTClaimsSet.Builder();

        log.debug("Request {} extension {}", ConnectRequestParameters.MAX_AGE, request.getExtensions().get(ConnectRequestParameters.MAX_AGE));
        log.debug("Request {} extension {}", OIDCConstants.ID_TOKEN, request.getExtensions().get(OIDCConstants.ID_TOKEN));
        log.debug("Client require authN time {}", client.getRequireAuthTime());

        calculateAuthTimeClaim(request, idClaims);

        idClaims.issueTime(issueTime);

        calculateAmrAndAcrClaims(accessToken, idClaims);
        calculateExpirationClaim(client, idClaims);

        idClaims.issuer(configBean.getIssuer());
        log.debug("issuer is set to {}", configBean.getIssuer());

        idClaims.subject(sub);
        log.debug("sub is set to {}", sub);

        idClaims.audience(Lists.newArrayList(client.getClientId()));
        log.debug("audience is set to {}", client.getClientId());

        final String jwtId = UUID.randomUUID().toString();
        idClaims.jwtID(jwtId);
        log.debug("JWT id is set to {}", jwtId);
        
        calculateNonceClaim(request, idClaims);

        final Set<String> responseTypes = request.getResponseTypes();

        calculateAtHashClaim(accessToken, signingAlg, idClaims, responseTypes);

        JWT idToken = null;
        if (client.getIdTokenEncryptedResponseAlg() != null
                && !client.getIdTokenEncryptedResponseAlg().equals(Algorithm.NONE)
                && client.getIdTokenEncryptedResponseEnc() != null
                && !client.getIdTokenEncryptedResponseEnc().equals(Algorithm.NONE)
                && (!Strings.isNullOrEmpty(client.getJwksUri()) || client.getJwks() != null)) {

            idToken = encryptIdToken(client, idClaims);
        } else {
            idToken = signIdToken(client, signingAlg, idClaims);
        }

        log.debug("Mapping the idToken to the authentication of client {}",
                accessToken.getAuthenticationHolder().getClientId());
        return idToken;
        
//        idTokenEntity.setAuthenticationHolder(accessToken.getAuthenticationHolder());
//
//        // create a scope set with just the special "id-token" scope
//        final Set<String> idScopes = Sets.newHashSet(SystemScopeService.ID_TOKEN_SCOPE);
//        idTokenEntity.setScope(idScopes);
//        log.debug("Configured scopes for the idToken scope {} are {}",
//                SystemScopeService.ID_TOKEN_SCOPE, idScopes);
//
//        idTokenEntity.setClient(accessToken.getClient());
//
//        return idTokenEntity;
    }

    /**
     * Sign id token.
     *
     * @param client     the client
     * @param signingAlg the signing alg
     * @param idClaims   the id claims
     */
    private JWT signIdToken(final ClientDetailsEntity client, final JWSAlgorithm signingAlg,
                            final JWTClaimsSet.Builder idClaims) {
        log.debug("Client {} is configured to ignore encryption", client.getClientId());

        final JWT idToken;
        if (signingAlg.equals(Algorithm.NONE)) {
            idToken = new PlainJWT(idClaims.build());
            log.debug("Client {} is configured to use an unsigned idToken", client.getClientId());
        } else {
            if (signingAlg.equals(JWSAlgorithm.HS256)
                    || signingAlg.equals(JWSAlgorithm.HS384)
                    || signingAlg.equals(JWSAlgorithm.HS512)) {

                idToken = signIdTokenForHs256Hs384Hs512(client, signingAlg, idClaims);
            } else {
                idToken = signIdTokenWithDefaultService(client, signingAlg, idClaims);
            }
        }
        return idToken;
    }

    /**
     * Sign id token for hs 256 hs 384 hs 512 jwt.
     *
     * @param client     the client
     * @param signingAlg the signing alg
     * @param idClaims   the id claims
     * @return the jwt
     */
    private JWT signIdTokenForHs256Hs384Hs512(final ClientDetailsEntity client,
                                              final JWSAlgorithm signingAlg, final JWTClaimsSet.Builder idClaims) {
        final JWT idToken;
        log.debug("Client {} required a signed idToken with signing alg of {}",
                client.getClientId(), signingAlg);
        final JWSHeader header = new JWSHeader(signingAlg, null, null,
                null, null, null, null, null, null, null,
                jwtService.getDefaultSignerKeyId(),
                null, null);
        idToken = new SignedJWT(header, idClaims.build());

        final JWTSigningAndValidationService signer = symmetricCacheService.getSymmetricValidtor(client);

        // sign it with the client's secret
        signer.signJwt((SignedJWT) idToken);
        return idToken;
    }

    /**
     * Encrypt id token.
     *
     * @param client   the client
     * @param idClaims the id claims
     */
    private JWT encryptIdToken(final ClientDetailsEntity client, final JWTClaimsSet.Builder idClaims) {
        log.debug("Locating encrypter service for client {}", client.getClientId());
        final JWTEncryptionAndDecryptionService encrypter = encrypters.getEncrypter(client);

        if (encrypter == null) {
            log.error("Couldn't find encrypter for client: {} ", client.getClientId());
            return null;
        }
        log.debug("Found encrypter service for client {}.", client.getClientId());
        final JWTClaimsSet claims = idClaims.build();
        final EncryptedJWT idToken = new EncryptedJWT(new JWEHeader(client.getIdTokenEncryptedResponseAlg(),
                client.getIdTokenEncryptedResponseEnc()), claims);

        log.debug("Encrypting idToken with response alg {} and response encoding {} and claims {}",
                client.getIdTokenEncryptedResponseAlg(),
                client.getIdTokenEncryptedResponseEnc(), claims.getClaims().keySet());
        encrypter.encryptJwt(idToken);
        return idToken;
    }

    /**
     * Calculate at hash claim.
     *
     * @param accessToken   the access token
     * @param signingAlg    the signing alg
     * @param idClaims      the id claims
     * @param responseTypes the response types
     */
    private void calculateAtHashClaim(final OAuth2AccessTokenEntity accessToken,
                                      final JWSAlgorithm signingAlg, final JWTClaimsSet.Builder idClaims,
                                      final Set<String> responseTypes) {
        if (responseTypes.contains(OIDCConstants.TOKEN)) {
            // calculate the token hash
            final Base64URL atHash = IdTokenHashUtils.getAccessTokenHash(signingAlg, accessToken);
            idClaims.claim(OIDCConstants.AT_HASH, atHash);

            log.debug("{} is set to {}", OIDCConstants.AT_HASH, atHash);
        }
    }

    /**
     * Calculate nonce claim.
     *
     * @param request  the request
     * @param idClaims the id claims
     */
    private void calculateNonceClaim(final OAuth2Request request, final JWTClaimsSet.Builder idClaims) {
        final String nonce = (String) request.getExtensions().get(ConnectRequestParameters.NONCE);
        if (!Strings.isNullOrEmpty(nonce)) {
            idClaims.claim(ConnectRequestParameters.NONCE, nonce);
            log.debug("{} is set to {}", ConnectRequestParameters.NONCE, nonce);
        }
    }

    /**
     * Calculate auth time claim.
     *
     * @param request  the request
     * @param idClaims the id claims
     */
    private void calculateAuthTimeClaim(final OAuth2Request request, final JWTClaimsSet.Builder idClaims) {
        final long authTime = Long.parseLong(
                request.getExtensions().get(OIDCConstants.AUTH_TIME).toString()) / 1000;
        log.debug("Request contains {} extension. {} set to {}",
                ConnectRequestParameters.MAX_AGE, OIDCConstants.AUTH_TIME, authTime);
        idClaims.claim(OIDCConstants.AUTH_TIME, authTime);
    }

    /**
     * Calculate expiration claim.
     *
     * @param client   the client
     * @param idClaims the id claims
     */
    private void calculateExpirationClaim(final ClientDetailsEntity client,
                                          final JWTClaimsSet.Builder idClaims) {
        if (client.getIdTokenValiditySeconds() != null) {
            final long exp = client.getIdTokenValiditySeconds() * 1000L;
            final Date expiration = new Date(System.currentTimeMillis() + exp);
            idClaims.expirationTime(expiration);
            log.debug("Claim expiration is set to {}", expiration);
        }
    }

    /**
     * Sign id token with default service jwt.
     *
     * @param client     the client
     * @param signingAlg the signing alg
     * @param idClaims   the id claims
     * @return the jwt
     */
    private JWT signIdTokenWithDefaultService(final ClientDetailsEntity client,
                                              final JWSAlgorithm signingAlg,
                                              final JWTClaimsSet.Builder idClaims) {
        final JWT idToken;
        idClaims.claim(OIDCConstants.KID, jwtService.getDefaultSignerKeyId());
        log.debug("Client {} required a signed idToken with signing alg of {} and kid {}",
                client.getClientId(), signingAlg, jwtService.getDefaultSignerKeyId());

        final JWSHeader header = new JWSHeader(signingAlg, null,
                null, null, null, null, null, null, null, null,
                jwtService.getDefaultSignerKeyId(),
                null, null);

        idToken = new SignedJWT(header, idClaims.build());

        log.debug("Using the default signer service to sign the idToken. Default signing alg is {}",
                jwtService.getDefaultSigningAlgorithm());

        // sign it with the server's key
        jwtService.signJwt((SignedJWT) idToken);
        return idToken;
    }

    /**
     * Calculate amr and acr claims.
     *
     * @param accessToken the access token
     * @param idClaims    the id claims
     */
    private void calculateAmrAndAcrClaims(final OAuth2AccessTokenEntity accessToken,
                                          final JWTClaimsSet.Builder idClaims) {
        final OAuth2Authentication authN = accessToken.getAuthenticationHolder().getAuthentication();
        final Collection<GrantedAuthority> authorities = authN.getAuthorities();
        for (final GrantedAuthority authority : authorities) {
            log.debug("Evaluating authority {} of the authentication", authority);
            final AuthenticationClassRefAuthority acr =
                    AuthenticationClassRefAuthority.getAuthenticationClassRefAuthority(authority);
            if (acr != null) {
                idClaims.claim(OIDCConstants.ACR, acr.getAuthority());
                log.debug("Added {} claim as {}", OIDCConstants.ACR, acr.getAuthority());
            }
            final AuthenticationMethodRefAuthority amr =
                    AuthenticationMethodRefAuthority.getAuthenticationClassRefAuthority(authority);
            if (amr != null) {
                idClaims.claim(OIDCConstants.AMR, amr.getAuthority());
                log.debug("Added {} claim as {}", OIDCConstants.AMR, amr.getAuthority());
            }
        }
    }


    @Override
    public OAuth2AccessTokenEntity createRegistrationAccessToken(final ClientDetailsEntity client) {
        return createAssociatedToken(client, Sets.newHashSet(SystemScopeService.REGISTRATION_TOKEN_SCOPE));
    }

    @Override
    public OAuth2AccessTokenEntity createResourceAccessToken(final ClientDetailsEntity client) {
        return createAssociatedToken(client, Sets.newHashSet(SystemScopeService.RESOURCE_TOKEN_SCOPE));
    }

    @Override
    public OAuth2AccessTokenEntity rotateRegistrationAccessTokenForClient(final ClientDetailsEntity client) {
        // revoke any previous tokens
        final OAuth2AccessTokenEntity oldToken = tokenService.getRegistrationAccessTokenForClient(client);
        if (oldToken != null) {
            final Set<String> scope = oldToken.getScope();
            tokenService.revokeAccessToken(oldToken);
            return createAssociatedToken(client, scope);
        } else {
            return null;
        }
    }

    /**
     * Create associated token o auth 2 access token entity.
     *
     * @param client the client
     * @param scope  the scope
     * @return the o auth 2 access token entity
     */
    private OAuth2AccessTokenEntity createAssociatedToken(final ClientDetailsEntity client, final Set<String> scope) {

        // revoke any previous tokens that might exist, just to be sure
        final OAuth2AccessTokenEntity oldToken = tokenService.getRegistrationAccessTokenForClient(client);
        if (oldToken != null) {
            tokenService.revokeAccessToken(oldToken);
        }

        // create a new token

        final Map<String, String> authorizationParameters = Maps.newHashMap();
        final OAuth2Request clientAuth = new OAuth2Request(authorizationParameters, client.getClientId(),
                Sets.newHashSet(new SimpleGrantedAuthority(OIDCConstants.ROLE_CLIENT)), true,
                scope, null, null, null, null);
        final OAuth2Authentication authentication = new OAuth2Authentication(clientAuth, null);

        final OAuth2AccessTokenEntity token = new OAuth2AccessTokenEntity();
        token.setClient(client);
        token.setScope(scope);

        AuthenticationHolderEntity authHolder = new AuthenticationHolderEntity();
        authHolder.setAuthentication(authentication);
        authHolder = authenticationHolderRepository.save(authHolder);
        token.setAuthenticationHolder(authHolder);

        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(Lists.newArrayList(client.getClientId()))
                .issuer(configBean.getIssuer())
                .issueTime(new Date())
                .expirationTime(token.getExpiration())
                .jwtID(UUID.randomUUID().toString())
                .build();

        final JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();
        final JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null, null,
                jwtService.getDefaultSignerKeyId(),
                null, null);
        final SignedJWT signed = new SignedJWT(header, claims);

        jwtService.signJwt(signed);

        token.setJwt(signed);

        return token;
    }

    /**
     * Gets config bean.
     *
     * @return the config bean
     */
    public ConfigurationPropertiesBean getConfigBean() {
        return configBean;
    }

    /**
     * Sets config bean.
     *
     * @param bean the bean
     */
    public void setConfigBean(final ConfigurationPropertiesBean bean) {
        this.configBean = bean;
    }

    /**
     * Gets jwt service.
     *
     * @return the jwt service
     */
    public JWTSigningAndValidationService getJwtService() {
        return jwtService;
    }

    /**
     * Sets jwt service.
     *
     * @param svc the svc
     */
    public void setJwtService(final JWTSigningAndValidationService svc) {
        this.jwtService = svc;
    }

    /**
     * Gets authentication holder repository.
     *
     * @return the authentication holder repository
     */
    public AuthenticationHolderRepository getAuthenticationHolderRepository() {
        return authenticationHolderRepository;
    }

    /**
     * Sets authentication holder repository.
     *
     * @param repo the repo
     */
    public void setAuthenticationHolderRepository(
            final AuthenticationHolderRepository repo) {
        this.authenticationHolderRepository = repo;
    }

}
