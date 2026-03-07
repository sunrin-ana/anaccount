package st.ana.accounts.masterkey.config;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.time.Instant;

@Configuration
@EnableWebSecurity
public class MaterCodeConfig {

    /***
     * AMS의 마스터키 기반 OTP는 2011년 1월 1일을 기준으로 합니다. 따라서, 현재시각에서 1293807600s을 뺀 시간을 사용합니다.
     *
     * @return AnA 주체 시간 (sec)
     */
    @Bean
    public TimeProvider timeProvider() {
        return () -> (Instant.now().getEpochSecond() - 1293807600L);
    }

    /**
     * CodeGenerator를 생성합니다. 이 빈은 MasterCodeService에서 마스터코드 생성을 위해 사용됩니다.
     * @return CodeGenerator
     */
    @Bean
    public CodeGenerator codeGenerator() {
        return new DefaultCodeGenerator();
    }

    /**
     * CodeVerifier를 생성합니다. 이 빈은 MasterCodeService에서 마스터코드 검증에 사용됩니다.
     * @return CodeVerifier
     */
    @Bean
    public CodeVerifier codeVerifier() {
        return new DefaultCodeVerifier(codeGenerator(), timeProvider());
    }
}
