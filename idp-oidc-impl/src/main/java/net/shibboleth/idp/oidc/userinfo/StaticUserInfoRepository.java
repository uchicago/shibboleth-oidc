package net.shibboleth.idp.oidc.userinfo;

import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Repository;

import java.util.HashSet;
import java.util.Set;

@Repository("staticUserInfoRepository")
@Primary
public class StaticUserInfoRepository implements UserInfoRepository {
    private final Set<UserInfo> userInfos = new HashSet<>();

    @Override
    public UserInfo getByUsername(final String s) {
        for (final UserInfo identifier : userInfos) {
            if (identifier.getPreferredUsername().equals(s)) {
                return identifier;
            }
        }
        return null;
    }

    @Override
    public UserInfo getByEmailAddress(final String s) {
        for (final UserInfo identifier : userInfos) {
            if (identifier.getEmail().equals(s)) {
                return identifier;
            }
        }
        return null;
    }
}
