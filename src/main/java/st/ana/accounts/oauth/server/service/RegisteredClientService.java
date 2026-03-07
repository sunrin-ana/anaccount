package st.ana.accounts.oauth.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import st.ana.accounts.oauth.server.model.OAuthClient;
import st.ana.accounts.oauth.server.repository.OAuthClientRepository;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RegisteredClientService implements RegisteredClientRepository {

    private final OAuthClientRepository clientRepository;
    private final ObjectMapper objMapper = new ObjectMapper();

    @Override
    public void save(RegisteredClient registeredClient) {
        try {
            OAuthClient client = OAuthClient.builder()
                    .id(registeredClient.getId())
                    .name(registeredClient.getClientName())
                    .secret(registeredClient.getClientSecret())
                    .scopes(String.join(",", registeredClient.getScopes()))
                    .tokenSettings(objMapper.writeValueAsString(registeredClient.getTokenSettings().getSettings()))
                    .clientSettings(objMapper.writeValueAsString(registeredClient.getClientSettings().getSettings()))
                    .authenticationMethods(registeredClient.getClientAuthenticationMethods()
                            .stream()
                            .map(ClientAuthenticationMethod::getValue)
                            .collect(Collectors.joining(","))
                    ).redirectUris(String.join(",", registeredClient.getRedirectUris()))
                    .postLogoutRedirectUris(String.join(",", registeredClient.getPostLogoutRedirectUris()))
                    .authorizationGrantTypes(registeredClient.getAuthorizationGrantTypes()
                            .stream()
                            .map(AuthorizationGrantType::getValue)
                            .collect(Collectors.joining(","))
                    ).build();

            clientRepository.save(client);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public @Nullable RegisteredClient findById(String id) {
        return findByClientId(id);
    }

    @Override
    public @Nullable RegisteredClient findByClientId(String clientId) {
        Optional<OAuthClient> client = clientRepository.findById(clientId);
        if (client.isEmpty()) return null;

        try {
            return RegisteredClient.withId(clientId)
                    .clientId(clientId)
                    .clientSecret(client.get().getSecret())
                    .scopes(s -> s.addAll(Arrays.asList(client.get().getScopes().split(","))))
                    .tokenSettings(TokenSettings.withSettings(objMapper.readValue(client.get().getTokenSettings(), Map.class)).build())
                    .clientSettings(ClientSettings.withSettings(objMapper.readValue(client.get().getClientSettings(), Map.class)).build())
                    .clientAuthenticationMethods(s -> s.addAll(Arrays.stream(client.get().getAuthenticationMethods().split(","))
                            .map(ClientAuthenticationMethod::valueOf)
                            .collect(Collectors.toSet())))
                    .redirectUris(s -> s.addAll(Arrays.asList(client.get().getRedirectUris().split(","))))
                    .postLogoutRedirectUris(s -> s.addAll(Arrays.asList(client.get().getPostLogoutRedirectUris().split(","))))
                    .authorizationGrantTypes(s -> s.addAll(Arrays.stream(client.get().getAuthorizationGrantTypes().split(","))
                            .map(AuthorizationGrantType::new)
                            .collect(Collectors.toSet())))
                    .authorizationGrantType(new AuthorizationGrantType(client.get().getAuthorizationGrantTypes()))
                    .build();
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
