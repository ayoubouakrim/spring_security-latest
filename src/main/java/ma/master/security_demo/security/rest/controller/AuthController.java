package ma.master.security_demo.security.rest.controller;

import ma.master.ai_quizs.security.beans.User;
import ma.master.ai_quizs.security.exceptions.UserAlreadyExistsException;
import ma.master.ai_quizs.security.jwt.JwtUtils;
import ma.master.ai_quizs.security.rest.dto.request.LoginRequest;
import ma.master.ai_quizs.security.rest.dto.request.SignupRequest;
import ma.master.ai_quizs.security.rest.dto.response.JwtResponse;
import ma.master.ai_quizs.security.rest.dto.response.MessageResponse;
import ma.master.ai_quizs.security.service.facade.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserService userService;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        User userDetails = (User) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(userDetails.getId(),
                jwt,
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }


    @PostMapping("/signup")
    public ResponseEntity<?>  register(@RequestBody SignupRequest signupRequest){
        try {
            userService.save(signupRequest);
            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
        } catch (UserAlreadyExistsException e) {
            return ResponseEntity.badRequest().body(new MessageResponse(e.getMessage()));
        }

    }



}
