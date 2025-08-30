package ma.master.security_demo.security.dao;

import ma.master.ai_quizs.security.beans.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDao extends JpaRepository<User, Long> {

    public User findByUsername(String username);


    public User findByEmail(String email);
}
