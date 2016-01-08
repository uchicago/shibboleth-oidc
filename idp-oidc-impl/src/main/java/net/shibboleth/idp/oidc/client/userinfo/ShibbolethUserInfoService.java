package net.shibboleth.idp.oidc.client.userinfo;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.PairwiseIdentiferService;
import org.mitre.openid.connect.service.UserInfoService;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;


@Service("openIdConnectUserInfoService")
@Primary
public class ShibbolethUserInfoService implements UserInfoService {

    private ProfileRequestContext profileRequestContext;

    @Autowired
    @Qualifier("staticUserInfoRepository")
    private StaticUserInfoRepository userInfoRepository;

    @Autowired
    private ClientDetailsEntityService clientService;

    @Autowired
    private PairwiseIdentiferService pairwiseIdentifierService;

    @Override
    public UserInfo getByUsername(final String username) {
        return userInfoRepository.getByUsername(username);
    }

    public void initialize(final ProfileRequestContext prc) {
        this.profileRequestContext = prc;
        this.userInfoRepository.initialize(prc);
    }

    @Override
    public UserInfo getByUsernameAndClientId(final String username, final String clientId) {

        final ClientDetailsEntity client = clientService.loadClientByClientId(clientId);
        final UserInfo userInfo = getByUsername(username);

        if (client == null || userInfo == null) {
            return null;
        }

        if (ClientDetailsEntity.SubjectType.PAIRWISE.equals(client.getSubjectType())) {
            final String pairwiseSub = pairwiseIdentifierService.getIdentifier(userInfo, client);
            userInfo.setSub(pairwiseSub);
        }

        return userInfo;

    }

    @Override
    public UserInfo getByEmailAddress(final String email) {
        return userInfoRepository.getByEmailAddress(email);
    }
}
