package com.ThymeleafExample.Thymeleaf.Repository;

import com.ThymeleafExample.Thymeleaf.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {
    User findByUsername(String username);
    boolean existsByUsernameOrEmail(String username,String email);
}
