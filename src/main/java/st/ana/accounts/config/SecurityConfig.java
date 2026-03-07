package st.ana.accounts.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import st.ana.accounts.oauth.client.OIDCUserService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final OIDCUserService oidcUserService;

    public SecurityConfig(OIDCUserService oidcUserService) {
        this.oidcUserService = oidcUserService;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/signup", "/oauth2/consent", "/device-code", "/css/**", "/images/**", "/error").permitAll()
                .requestMatchers("/signup").hasRole("UNKNOWN")
                .anyRequest().authenticated()
            ).oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/continue")
                .userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcUserService))
            ).logout(
                    logout -> logout
                            .logoutUrl("/logout")
                            .logoutSuccessUrl("/login")
                            .invalidateHttpSession(true)
                            .deleteCookies("JSESSIONID")
            );

        return http.build();
    }
}
