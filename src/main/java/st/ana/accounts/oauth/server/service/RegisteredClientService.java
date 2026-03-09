package st.ana.accounts.oauth.server.service;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import st.ana.accounts.oauth.server.model.OAuthClient;
import st.ana.accounts.oauth.server.repository.OAuthClientRepository;

@Service
@RequiredArgsConstructor
public class RegisteredClientService implements RegisteredClientRepository {

    private final OAuthClientRepository clientRepository;
    private final ObjectMapper objMapper;

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

        return RegisteredClient.withId(clientId)
                .clientId(clientId)
                .clientName(client.get().getName())
                .clientSecret(client.get().getSecret())
                .scopes(s -> s.addAll(client.get().getScopes()))
                .tokenSettings(TokenSettings.builder()
                        .settings(s -> {
                            try {
                                s.putAll(fixDurations(objMapper.readValue(client.get().getTokenSettings(), Map.class)));
                            } catch (JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        })
                        .build())
                .clientSettings(ClientSettings.builder()
                        .settings(s -> {
                            try {
                                s.putAll(objMapper.readValue(client.get().getClientSettings(), Map.class));
                            } catch (JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        })
                        .build())
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
    }

    private static final Set<String> DURATION_KEYS = Set.of(
            "settings.token.authorization-code-time-to-live",
            "settings.token.access-token-time-to-live",
            "settings.token.refresh-token-time-to-live",
            "settings.token.device-code-time-to-live"
    );

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Map<String, Object> fixDurations(Map<String, Object> settings) {
        Map<String, Object> result = new HashMap<>(settings);
        for (String key : DURATION_KEYS) {
            Object value = result.get(key);
            if (value instanceof String s) {
                result.put(key, Duration.parse(s));
            } else if (value instanceof Number n) {
                long seconds = n.longValue();
                long nanos = (long) ((n.doubleValue() - seconds) * 1_000_000_000L);
                result.put(key, Duration.ofSeconds(seconds, nanos));
            }
        }
        
        Object tokenFormat = result.get("settings.token.access-token-format");
        if (tokenFormat instanceof Map map) {
            if (map.containsKey("value")) {
                result.put("settings.token.access-token-format", new OAuth2TokenFormat(map.get("value").toString()));
            }
        } else if (tokenFormat instanceof String str) {
            result.put("settings.token.access-token-format", new OAuth2TokenFormat(str));
        }
        
        return result;
    }
}
