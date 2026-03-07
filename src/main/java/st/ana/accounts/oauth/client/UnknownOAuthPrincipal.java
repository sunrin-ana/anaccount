package st.ana.accounts.oauth.client;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

public class UnknownOAuthPrincipal implements OidcUser {
    private final OidcUser oauth2User;

    public UnknownOAuthPrincipal(OidcUser oauth2User) {
        this.oauth2User = oauth2User;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.oauth2User.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_UNKNOWN"));
    }

    @Override
    public String getName() {
        return this.oauth2User.getName();
    }

    @Override
    public Map<String, Object> getClaims() {
        return this.oauth2User.getClaims();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return this.oauth2User.getUserInfo();
    }

    @Override
    public OidcIdToken getIdToken() {
        return this.oauth2User.getIdToken();
    }
}
