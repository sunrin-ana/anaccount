package st.ana.accounts.oauth.server.dto;

import java.util.Map;
import java.util.Set;

public final class OAuthRequests {

    public record CreateClientRequest(
            String name,
            Set<String> scopes,
            Set<String> redirectUris,
            Set<String> postLogoutRedirectUris,
            Set<String> authenticationMethods,
            Set<String> authorizationGrantTypes,
            Set<String> allowedRoles,
            String amsRefer,
            Map<String, Object> clientSettings,
            Map<String, Object> tokenSettings
    ) {}

    public record UpdateClientRequest(
            String name,
            Set<String> scopes,
            Set<String> redirectUris,
            Set<String> postLogoutRedirectUris,
            Set<String> authenticationMethods,
            Set<String> authorizationGrantTypes,
            Set<String> allowedRoles,
            String amsRefer,
            Map<String, Object> clientSettings,
            Map<String, Object> tokenSettings
    ) {}
}
