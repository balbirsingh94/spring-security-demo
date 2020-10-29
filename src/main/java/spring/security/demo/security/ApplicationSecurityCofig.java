package spring.security.demo.security;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import spring.security.demo.auth.ApplicationUserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityCofig extends WebSecurityConfigurerAdapter{

	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired
	UserDetailsService userDetailsService;
	
	@Autowired
	ApplicationUserService applicationUserService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/","index","/css/*","/js/*").permitAll()
//			.antMatchers("/student/*").hasRole(STUDENT.name())
//			.antMatchers(HttpMethod.POST,"/management/*").hasAuthority(STUDENT_WRITE.getPermission())
//			.antMatchers(HttpMethod.PUT,"/management/*").hasAuthority(STUDENT_WRITE.getPermission())
//			.antMatchers(HttpMethod.DELETE,"/management/*").hasAuthority(STUDENT_WRITE.getPermission())
//			.antMatchers(HttpMethod.GET,"/management/*").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
			.anyRequest()
			.authenticated()
			.and()
//			.httpBasic();
			.formLogin()
				.loginPage("/login").permitAll()
				.defaultSuccessUrl("/courses",true)
				.usernameParameter("username")			// default username
				.passwordParameter("password")			// default password
			.and()
			.rememberMe()  // default 2 weeks
				.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
				.key("sometingVerySecured")
				.userDetailsService(userDetailsService)
				.rememberMeParameter("remember-me") 	// default remember-me
			.and()
			.logout()
				.logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.GET.name()))
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID","remember-me")
				.logoutSuccessUrl("/login");
		
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}
	
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}
	
	/*
	 * @Override
	 * 
	 * @Bean public UserDetailsService userDetailsServiceBean() throws Exception {
	 * UserDetails jamesBondUser = User.builder() .username("jamesbond")
	 * .password(passwordEncoder.encode("password")) // .roles(STUDENT.name()) //
	 * ROLE_STUDENT .authorities(STUDENT.getGrantedAuthorities()) .build();
	 * 
	 * UserDetails adminUser = User.builder() .username("admin")
	 * .password(passwordEncoder.encode("admin@123")) // .roles(ADMIN.name()) //
	 * ROLE_ADMIN .authorities(ADMIN.getGrantedAuthorities()) .build();
	 * 
	 * UserDetails adminTraineeUser = User.builder() .username("admintrainee")
	 * .password(passwordEncoder.encode("admin@123")) // .roles(ADMINTRAINEE.name())
	 * // ROLE_ADMINTRAINEE .authorities(ADMINTRAINEE.getGrantedAuthorities())
	 * .build();
	 * 
	 * return new InMemoryUserDetailsManager( jamesBondUser, adminUser,
	 * adminTraineeUser ); }
	 */
}
