package spring.security.demo.model;

public class Student {

	private Integer studentId;
	
	private String studentName;

	public Integer getStudentId() {
		return studentId;
	}

	public void setStudentId(Integer studentId) {
		this.studentId = studentId;
	}

	public String getStudentName() {
		return studentName;
	}

	public void setStudentName(String studentName) {
		this.studentName = studentName;
	}

	public Student(Integer studentId, String studentName) {
		super();
		this.studentId = studentId;
		this.studentName = studentName;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("Student {studentId:").append(studentId).append(", studentName:").append(studentName)
				.append("]");
		return builder.toString();
	}
	
	
	
}
