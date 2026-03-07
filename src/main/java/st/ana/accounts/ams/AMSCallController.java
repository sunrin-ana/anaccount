package st.ana.accounts.ams;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ams")
@PreAuthorize("hasAuthority('MASTERCODE')")
public class AMSCallController {

//    @DeleteMapping("/ref/{id}")
//    public void deleteReferral(@PathVariable Long id) {
//        //TODO: impl
//    }
}
