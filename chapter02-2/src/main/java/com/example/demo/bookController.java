package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class bookController {
    @Autowired
    Book book;

    @GetMapping("/book")
    public String book(){
        return book.toString();
    }
}
