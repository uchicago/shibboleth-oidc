package net.shibboleth.idp.oidc.client;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.repository.OAuth2ClientRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Component("staticOAuth2ClientRepository")
@Primary
public class StaticOAuth2ClientRepository implements OAuth2ClientRepository {

    @Resource(name="oidcClients")
    private Set<ClientDetailsEntity> clients = new HashSet<>();

    protected StaticOAuth2ClientRepository() {}

    public StaticOAuth2ClientRepository(final Set<ClientDetailsEntity> registeredClients) {
        this.clients = registeredClients;
    }

    @Override
    public ClientDetailsEntity getById(final Long aLong) {
        for (final ClientDetailsEntity client : clients) {
            if (client.getId().equals(aLong)) {
                return client;
            }
        }
        return null;
    }

    @Override
    public ClientDetailsEntity getClientByClientId(final String s) {
        for (final ClientDetailsEntity client : clients) {
            if (client.getClientId().equals(s)) {
                return client;
            }
        }
        return null;
    }

    @Override
    public ClientDetailsEntity saveClient(final ClientDetailsEntity clientDetailsEntity) {
        clients.add(clientDetailsEntity);
        return clientDetailsEntity;
    }

    @Override
    public void deleteClient(final ClientDetailsEntity clientDetailsEntity) {
        clients.remove(clientDetailsEntity);
    }

    @Override
    public ClientDetailsEntity updateClient(final Long aLong, final ClientDetailsEntity clientDetailsEntity) {
        return saveClient(clientDetailsEntity);
    }

    @Override
    public Collection<ClientDetailsEntity> getAllClients() {
        return clients;
    }
}
