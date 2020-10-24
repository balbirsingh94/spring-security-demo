package spring.security.demo.security;

public enum ApplicationUserPermissions {

	STUDENT_READ("student:read"),
	STUDENT_WRITE("student:write"),
	COURSE_READ("course:read"),
	COURSE_WRITE("course:write");
	
	private final String permission;

	public String getPermission() {
		return permission;
	}

	ApplicationUserPermissions(String permission) {
		this.permission = permission;
	}
}
