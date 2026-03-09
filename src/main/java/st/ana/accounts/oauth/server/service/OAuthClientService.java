package st.ana.accounts.oauth.server.service;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.google.common.hash.Hashing;

import dev.samstevens.totp.time.TimeProvider;
import lombok.RequiredArgsConstructor;
import st.ana.accounts.oauth.server.model.OAuthClient;
import st.ana.accounts.oauth.server.repository.OAuthClientRepository;

@Service
@RequiredArgsConstructor
public class OAuthClientService {

    private final OAuthClientRepository repository;
    private final TimeProvider timeProvider;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom random = new SecureRandom();

    public OAuthClient upsertClient(String id, OAuthClient build) {
        String rawSecret = generateClientSecret();
        String encodedSecret = passwordEncoder.encode(rawSecret);
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
                    client.setSecret(encodedSecret);
                    OAuthClient saved = repository.save(client);
                    saved.setSecret(rawSecret);
                    return saved;
                })
                .orElseGet(() -> {
                    build.setId(id);
                    build.setSecret(encodedSecret);
                    OAuthClient saved = repository.save(build);
                    saved.setSecret(rawSecret);
                    return saved;
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

    public String encodeSecret(String rawSecret) {
        return passwordEncoder.encode(rawSecret);
    }
}
