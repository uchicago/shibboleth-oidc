package net.shibboleth.idp.oidc.userinfo;

import org.mitre.openid.connect.model.Address;
import org.mitre.openid.connect.model.DefaultAddress;
import org.mitre.openid.connect.repository.AddressRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Repository;

import java.util.HashSet;
import java.util.Set;

@Repository("staticAddressRepository")
@Primary
public class StaticAddressRepository implements AddressRepository {

    private final Set<DefaultAddress> addresses = new HashSet<>();

    @Override
    public Address getById(final Long aLong) {
        for (final DefaultAddress address : addresses) {
            if (address.getId().equals(aLong)) {
                return address;
            }
        }
        return null;
    }
}
