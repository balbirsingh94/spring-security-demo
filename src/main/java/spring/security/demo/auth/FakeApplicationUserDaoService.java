package spring.security.demo.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

import spring.security.demo.security.ApplicationUserRoles;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUser()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUser(){
		List<ApplicationUser> applicationUserList = Lists.newArrayList(
				new ApplicationUser("jamesbond", passwordEncoder.encode("password"), ApplicationUserRoles.STUDENT.getGrantedAuthorities(), true, true, true, true),
				new ApplicationUser("admin", passwordEncoder.encode("admin@123"), ApplicationUserRoles.ADMIN.getGrantedAuthorities(), true, true, true, true),
				new ApplicationUser("admintrainee", passwordEncoder.encode("admin@123"), ApplicationUserRoles.ADMINTRAINEE.getGrantedAuthorities(), true, true, true, true)
				);
		return applicationUserList;
	}

}
