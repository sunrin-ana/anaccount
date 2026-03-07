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
                    .scopes(registeredClient.getScopes())
                    .tokenSettings(objMapper.writeValueAsString(registeredClient.getTokenSettings().getSettings()))
                    .clientSettings(objMapper.writeValueAsString(registeredClient.getClientSettings().getSettings()))
                    .authenticationMethods(registeredClient.getClientAuthenticationMethods()
                            .stream()
                            .map(ClientAuthenticationMethod::getValue)
                            .collect(Collectors.toSet())
                    ).redirectUris(registeredClient.getRedirectUris())
                    .postLogoutRedirectUris(registeredClient.getPostLogoutRedirectUris())
                    .authorizationGrantTypes(registeredClient.getAuthorizationGrantTypes()
                            .stream()
                            .map(AuthorizationGrantType::getValue)
                            .collect(Collectors.toSet())
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
                    .clientName(client.get().getName())
                    .clientSecret(client.get().getSecret())
                    .scopes(s -> s.addAll(client.get().getScopes()))
                    .tokenSettings(TokenSettings.withSettings(objMapper.readValue(client.get().getTokenSettings(), Map.class)).build())
                    .clientSettings(ClientSettings.withSettings(objMapper.readValue(client.get().getClientSettings(), Map.class)).build())
                    .clientAuthenticationMethods(s -> s.addAll(client.get().getAuthenticationMethods()
                            .stream()
                            .map(ClientAuthenticationMethod::new)
                            .collect(Collectors.toSet())))
                    .redirectUris(s -> s.addAll(client.get().getRedirectUris()))
                    .postLogoutRedirectUris(s -> s.addAll(client.get().getPostLogoutRedirectUris()))
                    .authorizationGrantTypes(s -> s.addAll(client.get().getAuthorizationGrantTypes()
                            .stream()
                            .map(AuthorizationGrantType::new)
                            .collect(Collectors.toSet())))
                    .build();
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
