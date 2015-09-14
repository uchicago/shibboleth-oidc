package net.shibboleth.idp.oidc.userinfo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * A userinfo endpoint for openid connect
 * that remaps the {@link org.mitre.openid.connect.web.UserInfoEndpoint}.
 */
@Controller("oidcUserInfoEndpoint")
@RequestMapping("/oidc/" + UserInfoEndpoint.URL)
public class UserInfoEndpoint extends org.mitre.openid.connect.web.UserInfoEndpoint {

}

