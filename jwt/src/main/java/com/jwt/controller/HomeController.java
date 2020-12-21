package com.jwt.controller;

import com.jwt.models.AuthenticationRequest;
import com.jwt.models.AuthenticationResponse;
import com.jwt.service.JwtUserDetailsService;
import com.jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class HomeController {

    @Autowired
     AuthenticationManager authenticationManager ;

    @Autowired
    JwtUserDetailsService userDetailsService ;

    @Autowired
    JwtUtil jwtUtil ;

    @GetMapping("/home")
    public String homeController(){
        return "Hello Jwt" ;
    }

    @RequestMapping(value = "/authenticate",method = RequestMethod.POST)
    public ResponseEntity<AuthenticationResponse> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {

       try {
           authenticationManager.authenticate(
                   new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
                           authenticationRequest.getPassword())
           );

       }catch (BadCredentialsException e){
           throw new Exception("Invalid username and password") ;
       }

       UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        String token = jwtUtil.generateToken(userDetails);
        return ResponseEntity.ok(new AuthenticationResponse(token));

    }
}
