package net.guides.springboot.registrationloginspringbootsecuritythymeleaf;

import ch.qos.logback.classic.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class RegistrationLoginSpringbootSecurityThymeleafApplication {
	private static final Logger logger = (Logger) LoggerFactory.getLogger(RegistrationLoginSpringbootSecurityThymeleafApplication.class);
	public static void main(String[] args) {
		SpringApplication.run(RegistrationLoginSpringbootSecurityThymeleafApplication.class, args);
		logger.info("Programm started");


	}

}
