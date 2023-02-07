package ru.alishev.springcourse.FirstSecurityApp.controllers;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.alishev.springcourse.FirstSecurityApp.dto.AuthenticationDto;
import ru.alishev.springcourse.FirstSecurityApp.dto.PersonDto;
import ru.alishev.springcourse.FirstSecurityApp.models.Person;
import ru.alishev.springcourse.FirstSecurityApp.security.JWTUtil;
import ru.alishev.springcourse.FirstSecurityApp.services.RegistrationService;
import ru.alishev.springcourse.FirstSecurityApp.util.PersonValidator;

import javax.validation.Valid;
import java.util.Map;

@RestController
@RequestMapping( "/auth" )
public class AuthController {

    private final PersonValidator personValidator;
    private final RegistrationService registrationService;
    private final JWTUtil jwtUtil;
    private final ModelMapper modelMapper;

    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthController(PersonValidator personValidator, RegistrationService registrationService, JWTUtil jwtUtil, ModelMapper modelMapper, AuthenticationManager authenticationManager) {
        this.personValidator = personValidator;
        this.registrationService = registrationService;
        this.jwtUtil = jwtUtil;
        this.modelMapper = modelMapper;
        this.authenticationManager = authenticationManager;
    }

    @GetMapping( "/login" )
    public String loginPage() {
        return "auth/login";
    }

    @GetMapping("/registration")
    public String registrationPage(@ModelAttribute( "person" ) Person person) {
        return "auth/registration";
    }

    @PostMapping("/registration")
    public Map<String, String> performRegistration(@RequestBody @Valid PersonDto personDto,
                                      BindingResult bindingResult) {

        Person person = convertToPerson(personDto);

        personValidator.validate(person, bindingResult);

        if(bindingResult.hasErrors()) {
            return Map.of("message", "Ошибка!");
        }

        registrationService.register(person);

        String token = jwtUtil.generateToken(person.getUsername());
        return Map.of("jwt-token", token);
    }
    @PostMapping( "/login" )
    public Map<String, String> performLogin(@RequestBody AuthenticationDto authenticationDto) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(authenticationDto.getUsername(),
                authenticationDto.getPassword());

        try {
            authenticationManager.authenticate(authenticationToken);
        }catch (BadCredentialsException e) {
            return Map.of("message", "Incorrect credentials!");
        }

        String token = jwtUtil.generateToken(authenticationDto.getUsername());
        return Map.of("jwt-token", token);
    }

    public Person convertToPerson(PersonDto personDto) {
        return this.modelMapper.map(personDto, Person.class);
    }
}
