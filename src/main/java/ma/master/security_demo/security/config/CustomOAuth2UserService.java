package ma.master.security_demo.security.config;

import ma.master.ai_quizs.security.beans.AuthProvider;
import ma.master.ai_quizs.security.beans.CustomOAuth2User;
import ma.master.ai_quizs.security.beans.Role;
import ma.master.ai_quizs.security.beans.User;
import ma.master.ai_quizs.security.dao.RoleDao;
import ma.master.ai_quizs.security.dao.UserDao;
import ma.master.ai_quizs.security.exceptions.OAuth2AuthenticationProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private RoleDao roleDao;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String email = oauth2User.getAttribute("email");
        String name = oauth2User.getAttribute("name");
        String providerId = oauth2User.getAttribute("id");

        if (email == null) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        User user = userDao.findByEmail(email);

        if (user == null) {
            user = createNewUser(email, name, providerId, registrationId);
        } else {
            user = updateExistingUser(user, name, registrationId);
        }


        return new CustomOAuth2User(oauth2User.getAttributes(), user);
    }

    private User createNewUser(String email, String name, String providerId, String registrationId) {
        User user = new User();
        user.setEmail(email);
        user.setUsername(name != null ? name : email);
        user.setProvider(AuthProvider.valueOf(registrationId.toUpperCase()));
        user.setProviderId(providerId);

        Set<Role> roles = new HashSet<>();
        Role userRole = roleDao.findByName("ROLE_USER");
        roles.add(userRole);
        user.setRoles(roles);

        return userDao.save(user);
    }

    private User updateExistingUser(User existingUser, String name, String registrationId) {
        if (name != null) {
            existingUser.setUsername(name);
        }
        return userDao.save(existingUser);
    }
}

