//package st.ana.accounts.masterkey.service;
//
//import com.google.common.hash.Hashing;
//import dev.samstevens.totp.code.CodeGenerator;
//import dev.samstevens.totp.code.CodeVerifier;
//import dev.samstevens.totp.exceptions.CodeGenerationException;
//import dev.samstevens.totp.time.TimeProvider;
//import jakarta.annotation.PostConstruct;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.scheduling.annotation.Scheduled;
//import org.springframework.stereotype.Service;
//import org.springframework.web.client.RestClient;
//
//import javax.crypto.*;
//import javax.crypto.spec.ChaCha20ParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//import java.io.File;
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.NoSuchAlgorithmException;
//import java.util.Arrays;
//import java.util.Base64;
//import java.util.Objects;
//import java.util.Set;
//
//@Service
//@Slf4j
//public class MasterCodeService {
//
//    private static final String MASTER_CODE_PATH = "/data/masterkey";
//
//    private final CodeVerifier verifier;
//    private final CodeGenerator generator;
//    private final TimeProvider timeProvider;
//    private final OauthClientService oauthService;
//    private String[] masterKey;
//
//    public MasterCodeService(
//            CodeVerifier verifier,
//            CodeGenerator generator,
//            TimeProvider timeProvider,
//            OauthClientService oauthService) {
//        this.verifier = verifier;
//        this.generator = generator;
//        this.timeProvider = timeProvider;
//        this.oauthService = oauthService;
//
//        File file = new File(MASTER_CODE_PATH);
//        if (!file.exists()) {
//            masterKey = System.getenv("AMS_INITIAL_MASTER_KEY").split("(?<=\\G.{64})");
//        } else if (file.isFile()) {
//            try {
//                masterKey = Files.readString(file.toPath()).split("(?<=\\G.{64})");
//            } catch (Exception e) {
//                log.error("Failed to read master key from file, falling back to environment variable", e);
//                masterKey = System.getenv("AMS_INITIAL_MASTER_KEY").split("(?<=\\G.{64})");
//            }
//        }else {
//            file.delete();
//            masterKey = System.getenv("AMS_INITIAL_MASTER_KEY").split("(?<=\\G.{64})");
//        }
//
//        System.out.println("masterKey: "+Arrays.toString(masterKey));
//    }
//
//    @PostConstruct
//    public void sendCredentialsToAMS() {
//        int count = 0;
//
//        while (true) {
//            if (count > 3) {
//                log.error("Failed to start");
//                System.exit(1);
//                return;
//            }
//
//            OauthClientDto.Response c;
//
//            c = oauthService.upsertClient(
//                    "ams",
//                    OauthClientDto.CreateRequest.builder()
//                            .clientName("AMS")
//                            .clientAuthenticationMethods(Set.of("client_secret_basic", "client_secret_post"))
//                            .authorizationGrantTypes(Set.of("authorization_code", "refresh_token"))
//                            .redirectUris(Set.of("https://mgnt.ana.st/oauth/anaccount/callback"))
//                            .postLogoutRedirectUris(Set.of())
//                            .scopes(Set.of("openid", "email", "profile"))
//                            .accessTokenTimeToLive(60 * 60 * 2)
//                            .refreshTokenTimeToLive(60 * 60 * 24)
//                            .reuseRefreshTokens(false)
//                            .build());
//
//            long current = timeProvider.getTime();
//            current -= current % 300;
//
//            try {
//                if (!Objects.requireNonNull(RestClient.builder()
//                                .build()
//                                .post()
//                                .uri(System.getenv("AMS_HOST") + "/masterkey/anaccount/secret")
//                                .body(encrypt(
//                                        "AMS_OAUTH_RESPONSE_" + c.getClientId() + "::" + c.getClientSecret(), current))
//                                .retrieve()
//                                .body(String.class))
//                        .equals("success")) {
//                    continue;
//                }
//            } catch (Exception e) {
//                count++;
//                log.error("Failed to send credentials to AMS", e);
//                continue;
//            }
//            return;
//        }
//    }
//
//    /**
//     * 마스터코드를 검증합니다.
//     *
//     * @return 마스터코드가 유효한지 여부
//     */
//    public boolean validateMasterKey(String code) {
//        long current = timeProvider.getTime();
//        current -= current % 300;
//        current /= 15;
//
//        String[] parts = code.split("(?<=\\G.{6})");
//
//        try {
//            return generator.generate(masterKey[2], current).equals(parts[0])
//                    && generator.generate(masterKey[1], current).equals(parts[1])
//                    && generator.generate(masterKey[0], current).equals(parts[2]);
//        } catch (CodeGenerationException e) {
//            throw new IllegalStateException("Master key generation failed: " + e.getMessage(), e);
//        }
//    }
//
//    @Scheduled(initialDelay = 1000 * 60 * 60 * 24, fixedRate = 1000 * 60 * 60 * 24)
//    public void requestMasterKeyUpdate() {
//        long current = timeProvider.getTime();
//        current -= current % 300;
//
//        try {
//            String val = RestClient.builder()
//                    .build()
//                    .patch()
//                    .uri("https://" + System.getenv("AMS_HOST") + "/api/masterkey/update")
//                    .header("X-CLIENT-ID", System.getenv("AMS_CLIENT_ID"))
//                    .body(encrypt("AMS_MASTER_" + masterKey[0] + masterKey[1] + masterKey[2], current))
//                    .retrieve()
//                    .body(String.class);
//
//            if (!Objects.requireNonNull(val).startsWith("AMS_MASTER_CHANGED_")) {
//                log.error("Unexpected response from master key update: {}", val);
//                return;
//            }
//
//            val = val.substring("AMS_MASTER_CHANGED_".length());
//
//            masterKey = val.split("(?<=\\G.{64})");
//
//            Files.writeString(Path.of(MASTER_CODE_PATH), val);
//        } catch (NoSuchAlgorithmException
//                | NoSuchPaddingException
//                | CodeGenerationException
//                | InvalidAlgorithmParameterException
//                | InvalidKeyException
//                | IllegalBlockSizeException
//                | BadPaddingException
//                | IOException e) {
//            throw new IllegalStateException("Master key update failed: " + e.getMessage(), e);
//        }
//    }
//
//    private String encrypt(String plainText, long current)
//            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
//            BadPaddingException, InvalidAlgorithmParameterException, CodeGenerationException {
//        Cipher cipher = Cipher.getInstance("ChaCha20");
//        long tcurrnet = current/15;
//
//        ChaCha20ParameterSpec param = new ChaCha20ParameterSpec(
//                Arrays.copyOfRange(
//                        Hashing.sha256()
//                                .hashBytes(generator
//                                        .generate(masterKey[1], tcurrnet)
//                                        .getBytes(StandardCharsets.UTF_8))
//                                .asBytes(),
//                        20,
//                        32),
//                Integer.parseInt(generator.generate(masterKey[0], tcurrnet)));
//
//        SecretKey key = new SecretKeySpec(
//                Hashing.sha256()
//                        .hashBytes(generator
//                                .generate(masterKey[2], tcurrnet)
//                                .getBytes(StandardCharsets.UTF_8))
//                        .asBytes(),
//                "ChaCha20");
//
//        cipher.init(Cipher.ENCRYPT_MODE, key, param);
//
//        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8))) + "@"
//                + Long.toHexString(current);
//    }
//}
