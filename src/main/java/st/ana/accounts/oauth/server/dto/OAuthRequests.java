package st.ana.accounts.oauth.server.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.Map;
import java.util.Set;

public final class OAuthRequests {

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
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

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record UpdateClientRequest(
            String id,
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

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record DeleteClientRequest(
            String id
    ) {}
}
