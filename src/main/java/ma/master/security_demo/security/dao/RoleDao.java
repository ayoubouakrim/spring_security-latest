package ma.master.security_demo.security.dao;

import ma.master.ai_quizs.security.beans.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleDao extends JpaRepository<Role, Long> {

    public Role findByName(String name);
}
