package st.ana.accounts.masterkey.service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.hash.Hashing;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.CodeGenerationException;
import dev.samstevens.totp.time.TimeProvider;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import st.ana.accounts.oauth.server.model.OAuthClient;
import st.ana.accounts.oauth.server.service.OAuthClientService;

@Service
@Slf4j
public class MasterCodeService {

    private static final String MASTER_CODE_PATH = "/data/masterkey";

    /**
     * AMS가 로그인 완료 후 돌아갈 기본 콜백 주소.
     *
     * <p>{@code AMS_HOST}는 AMS 백엔드 API 주소라서 OAuth 콜백으로 쓸 수 없다.
     * 콜백은 사용자가 실제로 보는 AMS 프론트엔드(mgnt.ana.st) 주소이므로 별도
     * 환경변수({@code AMS_REDIRECT_URI})로 지정하고, 없을 때만 이 값을 사용한다.
     */
    private static final String DEFAULT_AMS_REDIRECT_URI = "https://mgnt.ana.st/oauth/anaccount/callback";

    private final CodeVerifier verifier;
    private final CodeGenerator generator;
    private final TimeProvider timeProvider;
    private final OAuthClientService oauthService;
    private final ObjectMapper mapper;
    private String[] masterKey;

    @Value("${spring.profiles.active:}")
    private String activeProfile;

    public MasterCodeService(
            CodeVerifier verifier,
            CodeGenerator generator,
            TimeProvider timeProvider,
            OAuthClientService oauthService, ObjectMapper mapper) {
        this.verifier = verifier;
        this.generator = generator;
        this.timeProvider = timeProvider;
        this.oauthService = oauthService;
        this.mapper = mapper;

        File file = new File(MASTER_CODE_PATH);
        if (!file.exists()) {
            String mk = System.getenv("AMS_INITIAL_MASTER_KEY");
            masterKey = mk == null ? new String[0] : mk.split("(?<=\\G.{64})");
        } else if (file.isFile()) {
            try {
                masterKey = Files.readString(file.toPath()).split("(?<=\\G.{64})");
            } catch (Exception e) {
                log.error("Failed to read master key from file, falling back to environment variable", e);
                String mk2 = System.getenv("AMS_INITIAL_MASTER_KEY");
                masterKey = mk2 == null ? new String[0] : mk2.split("(?<=\\G.{64})");
            }
        }else {
            file.delete();
            String mk3 = System.getenv("AMS_INITIAL_MASTER_KEY");
            masterKey = mk3 == null ? new String[0] : mk3.split("(?<=\\G.{64})");
        }

        log.debug("masterKey: {}", Arrays.toString(masterKey));
    }

    @PostConstruct
    public void sendCredentialsToAMS() throws JsonProcessingException {
        if(activeProfile.equals("local")) return;
        int count = 0;

        while (true) {
            if (count > 3) {
                log.error("Failed to send credentials to AMS after retries");
                return;
            }

            OAuthClient c = oauthService.upsertClient(
                    "ams",
                    OAuthClient.builder()
                            .name("AMS")
                            .authenticationMethods(Set.of("client_secret_post"))
                            .authorizationGrantTypes(Set.of("authorization_code", "refresh_token"))
                            .redirectUris(Set.of(resolveAmsRedirectUri()))
                            .postLogoutRedirectUris(Set.of())
                            // Authlib(AMS)은 PKCE를 보내지 않으므로 proof key를 요구하면 authorize 단계에서 실패한다.
                            .clientSettings(mapper.writeValueAsString(ClientSettings.builder().requireProofKey(false).requireAuthorizationConsent(false).build().getSettings()))
                            .tokenSettings(mapper.writeValueAsString(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(2)).refreshTokenTimeToLive(Duration.ofDays(7)).build().getSettings()))
                            // AMS는 openid email profile을 요청한다. 등록되지 않은 scope를 요청하면 invalid_scope로 거절된다.
                            .scopes(Set.of("openid", "email", "profile"))
                            .build()
            );

            long current = timeProvider.getTime();
            current -= current % 300;

            try {
                if (!Objects.requireNonNull(RestClient.builder()
                                .build()
                                .post()
                                .uri(System.getenv("AMS_HOST") + "/masterkey/anaccount/secret")
                                .body(encrypt(
                                        "AMS_OAUTH_RESPONSE_" + c.getId() + "::" + c.getSecret(), current))
                                .retrieve()
                                .body(String.class))
                        .equals("success")) {
                    continue;
                }
            } catch (Exception e) {
                count++;
                log.error("Failed to send credentials to AMS", e);
                continue;
            }
            return;
        }
    }

    private static String resolveAmsRedirectUri() {
        String configured = System.getenv("AMS_REDIRECT_URI");
        if (configured != null && !configured.isBlank()) {
            return configured.trim();
        }
        return DEFAULT_AMS_REDIRECT_URI;
    }

    /**
     * 마스터코드를 검증합니다.
     *
     * @return 마스터코드가 유효한지 여부
     */
    public boolean validateMasterKey(String code) {
        if (code == null || code.length() != 18) return false;

        long current = timeProvider.getTime() / 15;
        long[] timeSteps = {current, current - 1, current + 1};

        String[] parts = code.split("(?<=\\G.{6})");
        if (parts.length != 3) return false;

        for (long t : timeSteps) {
            try {
                if (generator.generate(masterKey[2], t).equals(parts[0])
                        && generator.generate(masterKey[1], t).equals(parts[1])
                        && generator.generate(masterKey[0], t).equals(parts[2])) {
                    return true;
                }
            } catch (CodeGenerationException ignored) {}
        }
        return false;
    }

    @Scheduled(initialDelay = 1000 * 60 * 60 * 24, fixedRate = 1000 * 60 * 60 * 24)
    public void requestMasterKeyUpdate() {
        long current = timeProvider.getTime();
        current -= current % 300;

        try {
            String val = RestClient.builder()
                    .build()
                    .patch()
                    .uri(System.getenv("AMS_HOST") + "/api/masterkey/update")
                    .header("X-CLIENT-ID", System.getenv("AMS_CLIENT_ID"))
                    .body(encrypt("AMS_MASTER_" + masterKey[0] + masterKey[1] + masterKey[2], current))
                    .retrieve()
                    .body(String.class);

            if (!Objects.requireNonNull(val).startsWith("AMS_MASTER_CHANGED_")) {
                log.error("Unexpected response from master key update: {}", val);
                return;
            }

            val = val.substring("AMS_MASTER_CHANGED_".length());

            masterKey = val.split("(?<=\\G.{64})");

            Files.writeString(Path.of(MASTER_CODE_PATH), val);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | CodeGenerationException
                | InvalidAlgorithmParameterException
                | InvalidKeyException
                | IllegalBlockSizeException
                | BadPaddingException
                | IOException e) {
            throw new IllegalStateException("Master key update failed: " + e.getMessage(), e);
        }
    }

    private String encrypt(String plainText, long current)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, CodeGenerationException {
        Cipher cipher = Cipher.getInstance("ChaCha20");
        long tcurrnet = current/15;

        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(
                Arrays.copyOfRange(
                        Hashing.sha256()
                                .hashBytes(generator
                                        .generate(masterKey[1], tcurrnet)
                                        .getBytes(StandardCharsets.UTF_8))
                                .asBytes(),
                        20,
                        32),
                Integer.parseInt(generator.generate(masterKey[0], tcurrnet)));

        SecretKey key = new SecretKeySpec(
                Hashing.sha256()
                        .hashBytes(generator
                                .generate(masterKey[2], tcurrnet)
                                .getBytes(StandardCharsets.UTF_8))
                        .asBytes(),
                "ChaCha20");

        cipher.init(Cipher.ENCRYPT_MODE, key, param);

        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8))) + "@"
                + Long.toHexString(current);
    }
}
