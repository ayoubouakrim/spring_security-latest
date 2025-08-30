package ma.master.security_demo.security.service.impl;

import ma.master.ai_quizs.security.beans.Role;
import ma.master.ai_quizs.security.beans.User;
import ma.master.ai_quizs.security.dao.RoleDao;
import ma.master.ai_quizs.security.dao.UserDao;
import ma.master.ai_quizs.security.exceptions.UserAlreadyExistsException;
import ma.master.ai_quizs.security.rest.dto.request.SignupRequest;
import ma.master.ai_quizs.security.service.facade.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserServiceDetailsImpl implements UserService {


    private final UserDao userDao;
    private final RoleDao roleDao;

    @Lazy
    @Autowired
    private PasswordEncoder bCryptPasswordEncoder;

    public UserServiceDetailsImpl(UserDao userDao, RoleDao roleDao) {
        this.userDao = userDao;
        this.roleDao = roleDao;
    }



    @Override
    public String cryptPassword(String value) {
        return value == null ? null : bCryptPasswordEncoder.encode(value);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null) {
            throw new UsernameNotFoundException("User not found");
        } else {
            User user = userDao.findByUsername(username);
            if (user == null) {
                throw new UsernameNotFoundException("User not found");
            }
            return user;
        }
    }

    @Override
    public User findByUsername(String username) {
        if (username == null)
            return null;
        return userDao.findByUsername(username);
    }

    @Override
    public User findByEmail(String email) {
        if (email == null)
            return null;
        return userDao.findByEmail(email);
    }



    @Override
    public void save(SignupRequest signUpRequest) throws UserAlreadyExistsException {
        // Check if username already exists
        if (userDao.findByUsername(signUpRequest.getUsername()) != null) {
            throw new UserAlreadyExistsException("Username is already taken!");
        }

        // Check if email already exists
        if (userDao.findByEmail(signUpRequest.getEmail()) != null) {
            throw new UserAlreadyExistsException("Email is already in use!");
        }

        Set<Role> roles = new HashSet<>();
        Role userRole = roleDao.findByName("ROLE_USER");
        roles.add(userRole);

        // Create new user
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(bCryptPasswordEncoder.encode(signUpRequest.getPassword()));
        user.setRoles(roles);
        user.setAccountNonLocked(true);
        user.setEnabled(true);


        // Save user
        userDao.save(user);
    }


}
