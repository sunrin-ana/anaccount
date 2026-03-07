package st.ana.accounts.oauth.client;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import st.ana.accounts.user.model.User;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
public class OIDCUserPrincipal implements OidcUser {
    private final User user;

    public OIDCUserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of(
                "sub", user.getId(),
                "email", user.getEmail(),
                "generation", user.getGeneration()
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }

    @Override
    public String getName() {
        return user.getName();
    }

    @Override
    public Map<String, Object> getClaims() {
        return Map.of(
                "name", user.getName(),
                "google", user.getGoogleId()
        );
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return new OidcUserInfo(getAttributes());
    }

    @Override
    public OidcIdToken getIdToken() {
        return null;
    }
}
