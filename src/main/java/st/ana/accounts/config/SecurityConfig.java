package st.ana.accounts.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import st.ana.accounts.masterkey.security.MasterCodeAuthenticationFilter;
import st.ana.accounts.oauth.client.OIDCUserService;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final MasterCodeAuthenticationFilter masterCodeAuthenticationFilter;

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http, OIDCUserService oidcUserService) {
        http
            .addFilterBefore(masterCodeAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
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
            ).oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));

        return http.build();
    }
}
