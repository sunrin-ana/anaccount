package st.ana.accounts.oauth.server.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(
        name = "oauth2_registered_client",
        indexes = {@Index(name = "idx_oauth_client_ams_refer", columnList = "ams_refer")})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OAuthClient {

    @Id
    @Column(name = "id", nullable = false, unique = true, length = 256)
    private String id;

    @Column(name = "secret", length = 256)
    private String secret;

    @Column(name = "name", nullable = false, length = 200)
    private String name;

    @Column(name = "authentication_methods", nullable = false, length = 1000)
    private String authenticationMethods;

    @Column(name = "authorization_grant_types", nullable = false, length = 1000)
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris", length = 1000)
    private String redirectUris;

    @Column(name = "post_logout_redirect_uris", length = 1000)
    private String postLogoutRedirectUris;

    @Column(name = "scopes", nullable = false, length = 1000)
    private String scopes;

    @Column(name = "client_settings", nullable = false, length = 2000)
    private String clientSettings;

    @Column(name = "token_settings", nullable = false, length = 2000)
    private String tokenSettings;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_allowed_roles", joinColumns = @JoinColumn(name = "oauth_id"))
    @Column(name = "role")
    private Set<String> allowedRoles = new HashSet<>();

    @Column(name = "ams_refer")
    private String amsRefer;
}
