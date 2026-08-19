package com.dns;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class DnsApp {

    public static void main(String[] args) {
        SpringApplication.run(DnsApp.class, args);
    }

    @Bean
    public CommandLineRunner startDnsServer(@Autowired DNSServer dnsServer,
                                             @Autowired BlocklistService blocklistService) {
        return args -> {
            // fetch the live threat feed once at startup, before accepting any queries
            blocklistService.refreshFromLiveFeed();

            new Thread(() -> {
                try {
                    dnsServer.start();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
        };
    }
}
