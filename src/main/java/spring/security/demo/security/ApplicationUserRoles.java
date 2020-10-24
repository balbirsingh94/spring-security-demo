package spring.security.demo.security;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.google.common.collect.Sets;
import static spring.security.demo.security.ApplicationUserPermissions.*;

public enum ApplicationUserRoles {

	STUDENT(Sets.newHashSet()),
	ADMIN(Sets.newHashSet(STUDENT_READ,STUDENT_WRITE,COURSE_READ,COURSE_WRITE)),
	ADMINTRAINEE(Sets.newHashSet(STUDENT_READ,COURSE_READ));
	
	private final Set<ApplicationUserPermissions> permissions;

	public Set<ApplicationUserPermissions> getPermissions() {
		return permissions;
	}

	ApplicationUserRoles(Set<ApplicationUserPermissions> permissions) {
		this.permissions = permissions;
	}
	
	public Set<GrantedAuthority> getGrantedAuthorities(){
		Set<GrantedAuthority> permissions =  getPermissions().stream()
		.map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
		.collect(Collectors.toSet());
		
		permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
		
		return permissions;
	}
}
