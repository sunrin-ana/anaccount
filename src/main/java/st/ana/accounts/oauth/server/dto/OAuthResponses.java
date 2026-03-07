package st.ana.accounts.oauth.server.dto;

import org.jspecify.annotations.Nullable;

import java.util.Set;

public final class OAuthResponses {

    public record OAuthClientResponse(
            String id,
            String name,
            @Nullable String secret,
            Set<String> scopes,
            Set<String> redirectUris,
            Set<String> postLogoutRedirectUris,
            Set<String> authenticationMethods,
            Set<String> authorizationGrantTypes,
            Set<String> allowedRoles,
            String amsRefer
    ) {}
}
