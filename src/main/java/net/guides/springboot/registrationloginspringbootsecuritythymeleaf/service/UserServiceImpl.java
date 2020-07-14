package net.guides.springboot.registrationloginspringbootsecuritythymeleaf.service;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import net.guides.springboot.registrationloginspringbootsecuritythymeleaf.model.Role;
import net.guides.springboot.registrationloginspringbootsecuritythymeleaf.model.User;
import net.guides.springboot.registrationloginspringbootsecuritythymeleaf.repository.UserRepository;
import net.guides.springboot.registrationloginspringbootsecuritythymeleaf.web.dto.UserRegistrationDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;



@Service
public class UserServiceImpl implements UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public User save(UserRegistrationDto registration) {
        User user = new User();
        logger.info("Try to create new user");
        user.setFirstName(registration.getFirstName());
        logger.info("Try to get field from registration page");
        user.setLastName(registration.getLastName());
        logger.info("Try to get second field from reg page");
        user.setEmail(registration.getEmail());
        logger.info("Try to get email from reg page");
        user.setPassword(passwordEncoder.encode(registration.getPassword()));
        logger.info("Try to get password from reg page on hashing code");
        user.setRoles(Arrays.asList(new Role("ROLE_USER")));
        logger.info("Try to get role of user");
        return userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        logger.info("Try to join page by username");
        User user = userRepository.findByEmail(email);
        if (user == null) {
            logger.error("Invalid username or password");
            throw new UsernameNotFoundException("Invalid username or password.");
        }

        logger.info(user.getEmail() + " " +user.getPassword() + " try to take email and password from new creating user");
        return new org.springframework.security.core.userdetails.User(user.getEmail(),
                user.getPassword(),
                mapRolesToAuthorities(user.getRoles()));
    }

    private Collection < ? extends GrantedAuthority > mapRolesToAuthorities(Collection < Role > roles){
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

}