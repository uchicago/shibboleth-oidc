package net.shibboleth.idp.oidc.client;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.repository.OAuth2ClientRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import javax.annotation.PostConstruct;
import java.util.Set;


public class ShibbolethClientRepositoryBootstrapper {
    private final Logger log = LoggerFactory.getLogger(ShibbolethClientRepositoryBootstrapper.class);
    
    private final Set<ClientDetailsEntity> definedClients;

    @Autowired
    private OAuth2ClientRepository clientRepository;
    
    @Autowired
    private ApplicationContext applicationContext;

    public ShibbolethClientRepositoryBootstrapper(final Set<ClientDetailsEntity> definedClients) {
        this.definedClients = definedClients;
    }

    @PostConstruct
    public void bootstrap() {
        
        if (definedClients == null || definedClients.isEmpty()) {
            log.info("No OIDC clients are defined in the application context configuration.");
            return;
        }

        for (final ClientDetailsEntity client : definedClients) {
            try {
                log.debug("Attempting to save/update client id [{}] in the repository", client.getClientId());
                this.clientRepository.saveClient(client);
                log.info("Updated client id [{}] in the repository successfully", client.getClientId());
            } catch (final Exception e) {
                log.warn("Could not update client id [{}] in the repository", client.getClientId(), e);
            }
        }
    }
}
