package ma.master.security_demo.security.service.facade;

import ma.master.security_demo.security.beans.User;
import ma.master.security_demo.security.exceptions.UserAlreadyExistsException;
import ma.master.security_demo.security.rest.dto.request.SignupRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
    String cryptPassword(String value);

    UserDetails loadUserByUsername(String username);

    User findByUsername(String username);

    User findByEmail(String email);

    void save(SignupRequest signUpRequest) throws UserAlreadyExistsException;
}
