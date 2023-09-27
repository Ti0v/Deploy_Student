package com.ThymeleafExample.Thymeleaf.Service;

import com.ThymeleafExample.Thymeleaf.Entity.Student;
import com.ThymeleafExample.Thymeleaf.Repository.StudentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StudentService  {
    @Autowired

    private StudentRepository studentRepository;

    public StudentService(StudentRepository studentRepository) {
        super();
        this.studentRepository = studentRepository;
    }


    public List<Student> getAllStudents() {
        return studentRepository.findAll();
    }


    public Student saveStudent(Student student) {
        return studentRepository.save(student);
    }


    public Student getStudentById(Long id) {
        return studentRepository.findById(id).get();
    }


    public Student updateStudent(Student student) {
        return studentRepository.save(student);
    }


    public void deleteStudentById(Long id) {
        studentRepository.deleteById(id);
    }
}
