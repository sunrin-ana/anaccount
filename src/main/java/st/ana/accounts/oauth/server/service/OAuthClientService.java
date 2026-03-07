package st.ana.accounts.oauth.server.service;

import com.google.common.hash.Hashing;
import dev.samstevens.totp.time.TimeProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import st.ana.accounts.oauth.server.model.OAuthClient;
import st.ana.accounts.oauth.server.repository.OAuthClientRepository;

import java.security.SecureRandom;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class OAuthClientService {

    private final OAuthClientRepository repository;
    private final TimeProvider timeProvider;
    private final SecureRandom random = new SecureRandom();

    public OAuthClient upsertClient(String id, OAuthClient build) {
        return repository.findById(id)
                .map(client -> {
                    client.setName(build.getName());
                    client.setSecret(build.getSecret());
                    client.setScopes(build.getScopes());
                    client.setTokenSettings(build.getTokenSettings());
                    client.setClientSettings(build.getClientSettings());
                    client.setAuthenticationMethods(build.getAuthenticationMethods());
                    client.setRedirectUris(build.getRedirectUris());
                    client.setPostLogoutRedirectUris(build.getPostLogoutRedirectUris());
                    client.setAuthorizationGrantTypes(build.getAuthorizationGrantTypes());
                    client.setSecret(generateClientSecret());
                    return repository.save(client);
                })
                .orElseGet(() -> {
                    build.setId(id);
                    build.setSecret(generateClientSecret());
                    return repository.save(build);
                });
    }

    public String generateClientId() {
        return Base64.getEncoder().encodeToString(Hashing.sha512().hashLong(timeProvider.getTime()).asBytes())+"."+Base64.getEncoder().encodeToString(Hashing.sha512().hashLong(System.currentTimeMillis()).asBytes())+".accounts.ana.st";
    }

    public String generateClientSecret() {
        byte[] bytes = new byte[128];
        random.nextBytes(bytes);

        return Base64.getEncoder().encodeToString(Hashing.sha512().hashLong(timeProvider.getTime()).asBytes())+"."+Base64.getEncoder().encodeToString(Hashing.sha512().hashBytes(bytes).asBytes())+".SECRET.accounts.ana.st";
    }
}
