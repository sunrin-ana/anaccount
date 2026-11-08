package st.ana.accounts;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.OutputStream;
import java.net.CookieManager;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import st.ana.accounts.oauth.server.model.OAuthClient;
import st.ana.accounts.oauth.server.repository.OAuthClientRepository;

/**
 * Reproduces the full "third-party client logs in through anaccount" flow:
 *
 * <ol>
 *   <li>client redirects browser to {@code /oauth2/authorize} (not logged in)</li>
 *   <li>anaccount redirects to /login, saves the authorize request</li>
 *   <li>user logs in with Google (mocked discovery/token/jwks/userinfo)</li>
 *   <li>anaccount must redirect back to the client's registered redirect URI</li>
 * </ol>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("local")
class OAuthClientRedirectE2ETest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CLIENT_ID = "assignment";
    private static final String CLIENT_REDIRECT_URI = "https://assignment.ana.st/login/oauth2/code/anaccount";
    private static final String STATE = "client-state-1234";

    private static final HttpServer GOOGLE;
    private static final java.util.concurrent.ExecutorService GOOGLE_EXECUTOR;
    private static final KeyPair KEY_PAIR;
    private static final String ISSUER;
    private static volatile String idTokenNonce;

    static {
        try {
            KEY_PAIR = generateRsaKey();
            GOOGLE = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            GOOGLE_EXECUTOR = Executors.newFixedThreadPool(4, runnable -> {
                Thread thread = new Thread(runnable, "mock-google");
                thread.setDaemon(true);
                return thread;
            });
            GOOGLE.setExecutor(GOOGLE_EXECUTOR);
            ISSUER = "http://127.0.0.1:" + GOOGLE.getAddress().getPort();
            GOOGLE.createContext("/.well-known/openid-configuration", json(OAuthClientRedirectE2ETest::discovery));
            GOOGLE.createContext("/token", json(OAuthClientRedirectE2ETest::token));
            GOOGLE.createContext("/jwks", json(OAuthClientRedirectE2ETest::jwks));
            GOOGLE.createContext("/userinfo", json(OAuthClientRedirectE2ETest::userinfo));
            // Start from a daemon thread so the JDK HttpServer's non-configurable dispatcher
            // thread is a daemon too and cannot keep the Gradle test JVM alive.
            Thread starter = new Thread(GOOGLE::start, "mock-google-starter");
            starter.setDaemon(true);
            starter.start();
            starter.join(10_000);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void googleProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.registration.google.client-id", () -> "test-client");
        registry.add("spring.security.oauth2.client.registration.google.client-secret", () -> "test-secret");
        registry.add("spring.security.oauth2.client.registration.google.redirect-uri",
                () -> "{baseUrl}/login/oauth2/code/{registrationId}");
        registry.add("spring.security.oauth2.client.provider.google.issuer-uri", () -> ISSUER);
        registry.add("spring.security.oauth2.client.provider.google.authorization-uri", () -> ISSUER + "/authorize");
        registry.add("spring.security.oauth2.client.provider.google.token-uri", () -> ISSUER + "/token");
        registry.add("spring.security.oauth2.client.provider.google.jwk-set-uri", () -> ISSUER + "/jwks");
        registry.add("spring.security.oauth2.client.provider.google.user-info-uri", () -> ISSUER + "/userinfo");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private OAuthClientRepository clientRepository;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    private final HttpClient browser = HttpClient.newBuilder()
            .cookieHandler(new CookieManager())
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    @AfterAll
    static void stopGoogle() {
        GOOGLE.stop(0);
        GOOGLE_EXECUTOR.shutdownNow();
    }

    @BeforeEach
    void seedClient() {
        clientRepository.save(OAuthClient.builder()
                .id(CLIENT_ID)
                .name("Assignment")
                .secret("secret")
                .scopes(Set.of("openid", "email", "profile"))
                .redirectUris(Set.of(CLIENT_REDIRECT_URI))
                .postLogoutRedirectUris(Set.of())
                .authenticationMethods(Set.of("client_secret_post"))
                .authorizationGrantTypes(Set.of("authorization_code", "refresh_token"))
                .clientSettings("{}")
                .tokenSettings("{}")
                .allowedRoles(Set.of())
                .build());
    }

    @Test
    void clientSettingsDefaultToSas6BehaviourAndStoredValuesWin() {
        RegisteredClient defaulted = registeredClientRepository.findByClientId(CLIENT_ID);
        assertThat(defaulted.getClientSettings().isRequireProofKey())
                .as("empty stored client_settings must not force PKCE")
                .isFalse();
        assertThat(defaulted.getClientSettings().isRequireAuthorizationConsent()).isFalse();

        clientRepository.save(OAuthClient.builder()
                .id("pkce-client")
                .name("PKCE Client")
                .secret("secret")
                .scopes(Set.of("openid"))
                .redirectUris(Set.of("https://pkce.example/callback"))
                .postLogoutRedirectUris(Set.of())
                .authenticationMethods(Set.of("client_secret_post"))
                .authorizationGrantTypes(Set.of("authorization_code"))
                .clientSettings("{\"settings.client.require-proof-key\":true,"
                        + "\"settings.client.require-authorization-consent\":true}")
                .tokenSettings("{}")
                .allowedRoles(Set.of())
                .build());

        RegisteredClient explicit = registeredClientRepository.findByClientId("pkce-client");
        assertThat(explicit.getClientSettings().isRequireProofKey())
                .as("explicitly stored client_settings must override the defaults")
                .isTrue();
        assertThat(explicit.getClientSettings().isRequireAuthorizationConsent()).isTrue();
    }

    @Test
    void redirectsToRegisteredClientRedirectUriAfterLogin() throws Exception {
        String base = "http://localhost:" + this.port;

        // 1. third-party client sends the browser to the authorization endpoint
        String authorizeUrl = base + "/oauth2/authorize"
                + "?client_id=" + CLIENT_ID
                + "&response_type=code"
                + "&redirect_uri=" + enc(CLIENT_REDIRECT_URI)
                + "&scope=" + enc("openid email profile")
                + "&state=" + enc(STATE);
        HttpResponse<String> authorize = get(authorizeUrl);
        System.out.println("[E2E] authorize -> " + authorize.statusCode() + " " + location(authorize));

        assertThat(authorize.statusCode()).as("authorize should send anonymous user to login").isEqualTo(302);
        assertThat(location(authorize)).as("login redirect").isEqualTo(base + "/login");

        // 2. user clicks "Continue with Google"
        HttpResponse<String> googleRedirect = get(base + "/oauth2/authorization/google");
        System.out.println("[E2E] google authorize -> " + googleRedirect.statusCode() + " " + location(googleRedirect));
        assertThat(googleRedirect.statusCode()).isEqualTo(302);
        URI googleAuthorize = URI.create(location(googleRedirect));
        Map<String, String> googleParams = queryParams(googleAuthorize.getRawQuery());

        // 3. Google sends the user back to anaccount (mock id_token uses the nonce the
        //    authorization server sent)
        idTokenNonce = googleParams.get("nonce");
        HttpResponse<String> callback = get(base + "/login/oauth2/code/google"
                + "?code=mock-code&state=" + enc(googleParams.get("state")));
        System.out.println("[E2E] google callback -> " + callback.statusCode() + " " + location(callback));
        assertThat(callback.statusCode())
                .as("google callback should redirect to the saved authorize request, but was: %s",
                        location(callback))
                .isEqualTo(302);
        assertThat(location(callback)).as("saved request replay").startsWith(base + "/oauth2/authorize");

        // 4. the saved authorize request is replayed, now authenticated
        HttpResponse<String> completed = get(location(callback));
        System.out.println("[E2E] authorize replay -> " + completed.statusCode() + " " + location(completed));
        assertThat(completed.statusCode()).as("authorize replay").isEqualTo(302);
        assertThat(location(completed))
                .as("must redirect to the redirect URI registered for this OAuthClient")
                .startsWith(CLIENT_REDIRECT_URI);
        Map<String, String> responseParams = queryParams(URI.create(location(completed)).getRawQuery());
        assertThat(responseParams).containsEntry("state", STATE);
        assertThat(responseParams.get("code")).isNotBlank();
    }

    private HttpResponse<String> get(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                .GET()
                .build();
        return this.browser.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String location(HttpResponse<?> response) {
        return response.headers().firstValue("Location").orElseThrow();
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static Map<String, String> queryParams(String rawQuery) {
        Map<String, String> params = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) {
            return params;
        }
        for (String pair : rawQuery.split("&")) {
            int idx = pair.indexOf('=');
            String key = idx < 0 ? pair : pair.substring(0, idx);
            String value = idx < 0 ? "" : pair.substring(idx + 1);
            params.put(java.net.URLDecoder.decode(key, StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return params;
    }

    private static Map<String, Object> discovery() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("issuer", ISSUER);
        doc.put("authorization_endpoint", ISSUER + "/authorize");
        doc.put("token_endpoint", ISSUER + "/token");
        doc.put("userinfo_endpoint", ISSUER + "/userinfo");
        doc.put("jwks_uri", ISSUER + "/jwks");
        doc.put("response_types_supported", new String[]{"code"});
        doc.put("subject_types_supported", new String[]{"public"});
        doc.put("id_token_signing_alg_values_supported", new String[]{"RS256"});
        doc.put("scopes_supported", new String[]{"openid", "email", "profile"});
        doc.put("token_endpoint_auth_methods_supported", new String[]{"client_secret_post"});
        return doc;
    }

    private static Map<String, Object> token() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", "mock-access-token");
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);
        response.put("scope", "openid email profile");
        response.put("id_token", idToken());
        return response;
    }

    private static Map<String, Object> jwks() {
        RSAPublicKey publicKey = (RSAPublicKey) KEY_PAIR.getPublic();
        Map<String, Object> key = new LinkedHashMap<>();
        key.put("kty", "RSA");
        key.put("kid", "test-key");
        key.put("use", "sig");
        key.put("alg", "RS256");
        key.put("n", b64(publicKey.getModulus().toByteArray()));
        key.put("e", b64(publicKey.getPublicExponent().toByteArray()));
        return Map.of("keys", new Object[]{key});
    }

    private static Map<String, Object> userinfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("sub", "google-sub-1");
        info.put("email", "test@sunrint.hs.kr");
        info.put("email_verified", true);
        info.put("name", "Test User");
        info.put("given_name", "Test");
        return info;
    }

    private static String idToken() {
        try {
            long now = Instant.now().getEpochSecond();
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", ISSUER);
            claims.put("sub", "google-sub-1");
            claims.put("aud", "test-client");
            claims.put("iat", now);
            claims.put("exp", now + 3600);
            if (idTokenNonce != null) {
                claims.put("nonce", idTokenNonce);
            }
            claims.put("email", "test@sunrint.hs.kr");
            claims.put("email_verified", true);
            claims.put("name", "Test User");
            claims.put("given_name", "Test");

            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", "RS256");
            header.put("kid", "test-key");
            header.put("typ", "JWT");

            String signingInput = b64(MAPPER.writeValueAsBytes(header)) + "."
                    + b64(MAPPER.writeValueAsBytes(claims));
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(KEY_PAIR.getPrivate());
            signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + b64(signature.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static KeyPair generateRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static HttpHandler json(java.util.function.Supplier<Map<String, Object>> body) {
        return (HttpExchange exchange) -> {
            try (exchange) {
                byte[] bytes = MAPPER.writeValueAsBytes(body.get());
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(bytes);
                }
            }
        };
    }
}
