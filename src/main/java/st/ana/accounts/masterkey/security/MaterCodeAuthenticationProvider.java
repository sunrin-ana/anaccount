//package st.ana.accounts.masterkey.security;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.stereotype.Component;
//import st.ana.anaccount.masterkey.service.MasterCodeService;
//
//@Component
//public class MaterCodeAuthenticationProvider implements AuthenticationProvider {
//
//    private static final String PREFIX = "AnAMasterCode ";
//
//    @Autowired
//    private MasterCodeService service;
//
//    @Override
//    public Authentication authenticate(Authentication auth) throws AuthenticationException {
//        String masterCode = auth.getName();
//        if (masterCode.startsWith(PREFIX)) {
//            service.validateMasterKey(masterCode.substring(PREFIX.length()).trim());
//        }
//
//        return null;
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return false;
//    }
//}
