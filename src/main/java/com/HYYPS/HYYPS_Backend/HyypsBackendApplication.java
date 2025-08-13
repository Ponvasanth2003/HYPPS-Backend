package com.HYYPS.HYYPS_Backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableJpaRepositories
public class HyypsBackendApplication {
	public static void main(String[] args) {
		SpringApplication.run(HyypsBackendApplication.class, args);
	}
}
