package net.shibboleth.idp.oidc.config.scope;

import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.repository.SystemScopeRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.HashSet;
import java.util.Set;

/**
 * Repository to define system scopes statically.
 */
@Component("shibbolethSystemScopeRepository")
@Primary
public class ShibbolethSystemScopeRepository implements SystemScopeRepository {

    @Resource(name="supportedSystemScopes")
    private Set<SystemScope> scopes = new HashSet<>();

    protected ShibbolethSystemScopeRepository() {}

    public ShibbolethSystemScopeRepository(final Set<SystemScope> scopes) {
        this.scopes = scopes;
    }

    @Override
    public Set<SystemScope> getAll() {
        return this.scopes;
    }

    @Override
    public SystemScope getById(final Long aLong) {
        for (final SystemScope scope : scopes) {
            if (scope.getId().equals(aLong)) {
                return scope;
            }
        }
        return null;
    }

    @Override
    public SystemScope getByValue(final String s) {
        for (final SystemScope scope : scopes) {
            if (scope.getValue().equals(s)) {
                return scope;
            }
        }
        return null;
    }

    @Override
    public void remove(final SystemScope systemScope) {
        this.scopes.remove(systemScope);
    }

    @Override
    public SystemScope save(final SystemScope systemScope) {
        this.scopes.add(systemScope);
        return systemScope;
    }

    public static void main(String[] args) {
        System.out.println(Math.random());
    }
}
