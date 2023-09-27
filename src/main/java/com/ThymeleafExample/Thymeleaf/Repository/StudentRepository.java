package com.ThymeleafExample.Thymeleaf.Repository;

import com.ThymeleafExample.Thymeleaf.Entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentRepository  extends JpaRepository<Student,Long> {
}
