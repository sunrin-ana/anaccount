package st.ana.accounts.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import st.ana.accounts.masterkey.security.MasterCodeAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final MasterCodeAuthenticationFilter masterCodeAuthenticationFilter;

    public SecurityConfig(MasterCodeAuthenticationFilter masterCodeAuthenticationFilter) {
        this.masterCodeAuthenticationFilter = masterCodeAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/signup", "/oauth2/consent", "/device-code", "/css/**", "/images/**", "/error").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
            )
            .addFilterBefore(masterCodeAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
