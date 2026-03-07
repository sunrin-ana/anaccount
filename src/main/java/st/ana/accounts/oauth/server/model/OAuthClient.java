package st.ana.accounts.oauth.server.model;

import java.util.HashSet;
import java.util.Set;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_auth_methods", joinColumns = @JoinColumn(name = "oauth_id"))
    @Column(name = "method", nullable = false, length = 200)
    @Builder.Default
    private Set<String> authenticationMethods = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_grant_types", joinColumns = @JoinColumn(name = "oauth_id"))
    @Column(name = "grant_type", nullable = false, length = 200)
    @Builder.Default
    private Set<String> authorizationGrantTypes = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_redirect_uris", joinColumns = @JoinColumn(name = "oauth_id"))
    @Column(name = "uri", length = 1000)
    @Builder.Default
    private Set<String> redirectUris = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_post_logout_uris", joinColumns = @JoinColumn(name = "oauth_id"))
    @Column(name = "uri", length = 1000)
    @Builder.Default
    private Set<String> postLogoutRedirectUris = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_client_scopes", joinColumns = @JoinColumn(name = "oauth_id"))
    @Column(name = "scope", nullable = false, length = 200)
    @Builder.Default
    private Set<String> scopes = new HashSet<>();

    @Column(name = "client_settings", nullable = false, length = 2000)
    private String clientSettings;

    @Column(name = "token_settings", nullable = false, length = 2000)
    private String tokenSettings;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "oauth_allowed_roles", joinColumns = @JoinColumn(name = "oauth_id"))
    @Column(name = "role")
    @Builder.Default
    private Set<String> allowedRoles = new HashSet<>();

    @Column(name = "ams_refer")
    private String amsRefer;
}
