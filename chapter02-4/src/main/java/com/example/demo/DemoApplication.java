package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication

public class DemoApplication {



    public static void main(String[] args) {
//        SpringApplicationBuilder builder = new SpringApplicationBuilder(DemoApplication.class);
//        builder.application().setAdditionalProfiles("prod");
//        builder.run(args);
         SpringApplication.run(DemoApplication.class, args);
    }

}
