package st.ana.accounts.oauth.server.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import st.ana.accounts.oauth.client.OIDCUserPrincipal;
import st.ana.accounts.oauth.server.service.RegisteredClientService;
import st.ana.accounts.user.model.User;
import st.ana.accounts.user.repository.UserRepository;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class OAuthServerConfig {

    @Value("${spring.security.oauth2.authorizationserver.issuer:http://localhost:8080}")
    private String issuerUri;

    private final UserRepository userRepository;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, RegisteredClientService service) {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .securityContext(ctx -> ctx.securityContextRepository(new HttpSessionSecurityContextRepository()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .with(authorizationServerConfigurer, Customizer.withDefaults());

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(auth -> auth.consentPage("/oauth2/consent"))
                .oidc(oidc -> oidc.userInfoEndpoint(userInfo -> userInfo.userInfoMapper(
                        ctx -> {
                            OAuth2Authorization authorization = ctx.getAuthorization();
                            String principalName = authorization.getPrincipalName();

                            Set<String> scopes = authorization.getAuthorizedScopes();
                            User user = userRepository.findByHandle(principalName).orElse(null);

                            Map<String, Object> claims = processClaims(user, principalName, scopes);

                            return new OidcUserInfo(claims);
                        }
                )))
                .registeredClientRepository(service);

        http
                // 로그인 페이지로 이동
                .exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // 수락
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    private static @NonNull Map<String, Object> processClaims(User user, String id, Set<String> scopes) {
        Map<String, Object> claims = new HashMap<>();

        if (user != null) {
            claims.put("type", user.getGeneration()==-1?"user":"member");
            claims.put(StandardClaimNames.SUB, id);
            if (scopes.contains("email")) {
                claims.put(StandardClaimNames.EMAIL, user.getEmail());
            }
            if (scopes.contains("profile") && user.getName() != null) {
                claims.put(StandardClaimNames.NAME, user.getName());
                claims.put(StandardClaimNames.PREFERRED_USERNAME, user.getHandle());
                claims.put("generation", user.getGeneration());
            }
        }
        return claims;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) return;
            Authentication principal = context.getPrincipal();
            log.info("JWT : principal: {}", principal);
            OIDCUserPrincipal p = null;
            if (principal instanceof OAuth2AuthenticationToken token &&
                    token.getPrincipal() instanceof OIDCUserPrincipal oidcPrincipal) {
                p = oidcPrincipal;
            }
            if (p == null) return;

            String clientId = context.getRegisteredClient().getClientId();
            User user = p.getUser();
            context.getClaims().claim("client_id", clientId);
            context.getClaims().claim("user_id", user.getId());
            context.getClaims().claim("user_email", user.getEmail());
            context.getClaims().claim("user_handle", user.getHandle());
        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer(issuerUri).build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }
}
