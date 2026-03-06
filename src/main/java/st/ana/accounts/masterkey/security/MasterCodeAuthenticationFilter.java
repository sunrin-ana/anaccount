package st.ana.accounts.masterkey.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import st.ana.accounts.masterkey.service.MasterCodeService;

import java.io.IOException;

@Component
@Slf4j
public class MasterCodeAuthenticationFilter extends OncePerRequestFilter {

    private static final String HEADER_NAME = "Authorization";
    private static final String PREFIX = "AnAMasterCode ";

    private final MasterCodeService service;

    public MasterCodeAuthenticationFilter(MasterCodeService service) {
        this.service = service;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader(HEADER_NAME);

        // Auth 방식이 AnAMasterCode인지 확인
        if (header == null || !header.startsWith(PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        header = header.substring(PREFIX.length()).trim();

        // MasterCode 형식에 맞지 않으면 거부
        if (header.length() != 18) throw new BadCredentialsException("Invalid mastercode length received");


        if (!service.validateMasterKey(header)) {
            log.warn("Invalid mastercode received");
            throw new BadCredentialsException("Invalid mastercode received");
        }

        MasterCodeAuthentication authentication = new MasterCodeAuthentication();
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.debug("Object Type: {}", auth.getClass().getName());
        log.debug("Permission List: {}", auth.getAuthorities());
        log.debug("Auth?: {}", auth.isAuthenticated());

        filterChain.doFilter(request, response);
    }
}
