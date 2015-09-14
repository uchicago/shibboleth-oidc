package net.shibboleth.idp.oidc.userinfo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller("oidcUserInfoEndpoint")
@RequestMapping("/oidc/" + UserInfoEndpoint.URL)
public class UserInfoEndpoint extends org.mitre.openid.connect.web.UserInfoEndpoint {

}

