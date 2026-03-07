package st.ana.accounts.oauth.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import st.ana.accounts.user.model.User;
import st.ana.accounts.user.repository.UserRepository;

import java.util.Objects;
import java.util.Optional;

@Service
@Slf4j
public class OIDCUserService extends OidcUserService {
    private final UserRepository userRepository;

    public OIDCUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("Processing OAuth2 login for provider: {}", registrationId);

        return processOIDCUser(userRequest, oidcUser);
    }

    private OidcUser processOIDCUser(OAuth2UserRequest userRequest, OidcUser oidcUser) {
        String email = oidcUser.getAttribute("email");
        String name = oidcUser.getAttribute("name");
        String providerId = oidcUser.getAttribute("sub");
        String provider = userRequest.getClientRegistration().getRegistrationId();

        log.info("OIDC user - email: {}, name: {}, provider: {}", email, name, provider);

        // @sunrint.hs.kr
        if (!Objects.requireNonNull(email).endsWith("@sunrint.hs.kr")) {
            throw new OAuth2AuthenticationException("Only @sunrint.hs.kr email addresses are allowed");
        }

        Optional<User> user = userRepository.findByGoogleId(providerId);
        if (user.isEmpty()) {
            log.warn("User not found in database: {}", providerId);
            return new UnknownOAuthPrincipal(oidcUser);
        }

        return new OIDCUserPrincipal(user.get());
    }
}
