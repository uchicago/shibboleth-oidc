package net.shibboleth.idp.oidc.client.userinfo.authn;


import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
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
import org.mitre.openid.connect.service.OIDCTokenService;
import org.mitre.openid.connect.util.IdTokenHashUtils;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
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

@Primary
@Component("shibbolethAcrAwareTokenService")
public class ShibbolethAcrAwareTokenService implements OIDCTokenService {
    private static final Logger log = LoggerFactory.getLogger(ShibbolethAcrAwareTokenService.class);

    @Autowired
    private JWTSigningAndValidationService jwtService;

    @Autowired
    private AuthenticationHolderRepository authenticationHolderRepository;

    @Autowired
    private ConfigurationPropertiesBean configBean;

    @Autowired
    private ClientKeyCacheService encrypters;

    @Autowired
    private SymmetricKeyJWTValidatorCacheService symmetricCacheService;

    @Autowired
    private OAuth2TokenEntityService tokenService;

    @Override
    public OAuth2AccessTokenEntity createIdToken(final ClientDetailsEntity client, final OAuth2Request request,
                                                 final Date issueTime, final String sub, final OAuth2AccessTokenEntity accessToken) {

        JWSAlgorithm signingAlg = jwtService.getDefaultSigningAlgorithm();

        if (client.getIdTokenSignedResponseAlg() != null) {
            signingAlg = client.getIdTokenSignedResponseAlg();
        }

        final OAuth2AccessTokenEntity idTokenEntity = new OAuth2AccessTokenEntity();
        final JWTClaimsSet.Builder idClaims = new JWTClaimsSet.Builder();

        if (request.getExtensions().containsKey("max_age")
                || request.getExtensions().containsKey("idtoken")
                || (client.getRequireAuthTime() != null && client.getRequireAuthTime())) {

            if (request.getExtensions().get(AuthenticationTimeStamper.AUTH_TIMESTAMP) != null) {

                final Long authTimestamp = Long.parseLong((String) request.getExtensions().get(AuthenticationTimeStamper.AUTH_TIMESTAMP));
                if (authTimestamp != null) {
                    idClaims.claim("auth_time", authTimestamp / 1000L);
                }
            } else {
                // we couldn't find the timestamp!
                log.warn("Unable to find authentication timestamp! There is likely something wrong with the configuration.");
            }
        }

        idClaims.issueTime(issueTime);

        final OAuth2Authentication authN = accessToken.getAuthenticationHolder().getAuthentication();
        final Collection<GrantedAuthority> authorities = authN.getAuthorities();
        for (final GrantedAuthority authority : authorities) {
            log.debug("Evaluating authority {} of the authentication", authority);
            final AuthenticationClassRefAuthority acr = AuthenticationClassRefAuthority.getAuthenticationClassRefAuthority(authority);
            if (acr != null) {
                idClaims.claim("acr", acr.getAuthority());
                log.debug("Added acr claim as", acr.getAuthority());
            }
            final AuthenticationMethodRefAuthority amr = AuthenticationMethodRefAuthority.getAuthenticationClassRefAuthority(authority);
            if (amr != null) {
                idClaims.claim("amr", amr.getAuthority());
                log.debug("Added amr claim as", amr.getAuthority());
            }
        }

        if (client.getIdTokenValiditySeconds() != null) {
            final Date expiration = new Date(System.currentTimeMillis() + (client.getIdTokenValiditySeconds() * 1000L));
            idClaims.expirationTime(expiration);
            idTokenEntity.setExpiration(expiration);
            log.debug("Claim expiration is set to {}", expiration);
        }

        idClaims.issuer(configBean.getIssuer());
        log.debug("issuer is set to {}", configBean.getIssuer());

        idClaims.subject(sub);
        log.debug("sub is set to {}", sub);

        idClaims.audience(Lists.newArrayList(client.getClientId()));
        log.debug("audience is set to {}", client.getClientId());

        final String jwtId = UUID.randomUUID().toString();
        idClaims.jwtID(jwtId); // set a random NONCE in the middle of it
        log.debug("JWT id is set to {}", jwtId);


        final String nonce = (String) request.getExtensions().get("nonce");
        if (!Strings.isNullOrEmpty(nonce)) {
            idClaims.claim("nonce", nonce);
            log.debug("nonce is set to {}", nonce);
        }

        final Set<String> responseTypes = request.getResponseTypes();

        if (responseTypes.contains("token")) {
            // calculate the token hash
            final Base64URL at_hash = IdTokenHashUtils.getAccessTokenHash(signingAlg, accessToken);
            idClaims.claim("at_hash", at_hash);

            log.debug("at_hash is set to {}", at_hash);
        }

        if (client.getIdTokenEncryptedResponseAlg() != null && !client.getIdTokenEncryptedResponseAlg().equals(Algorithm.NONE)
                && client.getIdTokenEncryptedResponseEnc() != null && !client.getIdTokenEncryptedResponseEnc().equals(Algorithm.NONE)
                && (!Strings.isNullOrEmpty(client.getJwksUri()) || client.getJwks() != null)) {

            log.debug("Locating encrypter service for client {}", client.getClientId());
            final JWTEncryptionAndDecryptionService encrypter = encrypters.getEncrypter(client);

            if (encrypter != null) {

                log.debug("Found encrypter service for client {}.", client.getClientId());
                final JWTClaimsSet claims = idClaims.build();
                final EncryptedJWT idToken = new EncryptedJWT(new JWEHeader(client.getIdTokenEncryptedResponseAlg(),
                        client.getIdTokenEncryptedResponseEnc()), claims);

                log.debug("Encrypting idToken with response alg {} and response encoding {} and claims {}",
                        client.getIdTokenEncryptedResponseAlg(), client.getIdTokenEncryptedResponseEnc(), claims.getClaims().keySet());
                encrypter.encryptJwt(idToken);
                idTokenEntity.setJwt(idToken);
            } else {
                log.error("Couldn't find encrypter for client: {} ", client.getClientId());
            }
        } else {

            log.debug("Client {} is configured to ignore encryption", client.getClientId());

            final JWT idToken;
            if (signingAlg.equals(Algorithm.NONE)) {
                // unsigned ID token
                idToken = new PlainJWT(idClaims.build());
                log.debug("Client {} is configured to use an unsigned idToken", client.getClientId());
            } else {

                // signed ID token

                if (signingAlg.equals(JWSAlgorithm.HS256)
                        || signingAlg.equals(JWSAlgorithm.HS384)
                        || signingAlg.equals(JWSAlgorithm.HS512)) {

                    log.debug("Client {} required a signed idToken with signing alg of {}", client.getClientId(), signingAlg);
                    final JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null, null,
                            jwtService.getDefaultSignerKeyId(),
                            null, null);
                    idToken = new SignedJWT(header, idClaims.build());

                    final JWTSigningAndValidationService signer = symmetricCacheService.getSymmetricValidtor(client);

                    // sign it with the client's secret
                    signer.signJwt((SignedJWT) idToken);
                } else {

                    idClaims.claim("kid", jwtService.getDefaultSignerKeyId());
                    log.debug("Client {} required a signed idToken with signing alg of {} and kid {}",
                            client.getClientId(), signingAlg, jwtService.getDefaultSignerKeyId());

                    final JWSHeader header = new JWSHeader(signingAlg, null, null, null, null, null, null, null, null, null,
                            jwtService.getDefaultSignerKeyId(),
                            null, null);

                    idToken = new SignedJWT(header, idClaims.build());

                    log.debug("Using the default signer service to sign the idToken. Default signing alg is {}",
                            jwtService.getDefaultSigningAlgorithm());

                    // sign it with the server's key
                    jwtService.signJwt((SignedJWT) idToken);
                }
            }


            idTokenEntity.setJwt(idToken);
        }

        log.debug("Mapping the idToken to the authentication of client {}", accessToken.getAuthenticationHolder().getClientId());
        idTokenEntity.setAuthenticationHolder(accessToken.getAuthenticationHolder());

        // create a scope set with just the special "id-token" scope
        final Set<String> idScopes = Sets.newHashSet(SystemScopeService.ID_TOKEN_SCOPE);
        idTokenEntity.setScope(idScopes);
        log.debug("Configured scopes for the idToken scope {} are {}", SystemScopeService.ID_TOKEN_SCOPE, idScopes);

        idTokenEntity.setClient(accessToken.getClient());

        return idTokenEntity;
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

    private OAuth2AccessTokenEntity createAssociatedToken(final ClientDetailsEntity client, final Set<String> scope) {

        // revoke any previous tokens that might exist, just to be sure
        final OAuth2AccessTokenEntity oldToken = tokenService.getRegistrationAccessTokenForClient(client);
        if (oldToken != null) {
            tokenService.revokeAccessToken(oldToken);
        }

        // create a new token

        final Map<String, String> authorizationParameters = Maps.newHashMap();
        final OAuth2Request clientAuth = new OAuth2Request(authorizationParameters, client.getClientId(),
                Sets.newHashSet(new SimpleGrantedAuthority("ROLE_CLIENT")), true,
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
                .jwtID(UUID.randomUUID().toString()) // set a random NONCE in the middle of it
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

    public ConfigurationPropertiesBean getConfigBean() {
        return configBean;
    }


    public void setConfigBean(final ConfigurationPropertiesBean configBean) {
        this.configBean = configBean;
    }


    public JWTSigningAndValidationService getJwtService() {
        return jwtService;
    }


    public void setJwtService(final JWTSigningAndValidationService jwtService) {
        this.jwtService = jwtService;
    }


    public AuthenticationHolderRepository getAuthenticationHolderRepository() {
        return authenticationHolderRepository;
    }

    public void setAuthenticationHolderRepository(
            final AuthenticationHolderRepository authenticationHolderRepository) {
        this.authenticationHolderRepository = authenticationHolderRepository;
    }

}
