package com.example.ocean.model;

// Generated 13-May-2014 16:13:57 by Hibernate Tools 3.4.0.CR1

import java.util.HashSet;
import java.util.Set;

/**
 * User generated by hbm2java
 */
public class User implements java.io.Serializable {

	private String email;
	private String tel;
	private String postcode;
	private Set certificates = new HashSet(0);
	private Set keyrings = new HashSet(0);

	public User() {
	}

	public User(String email, String tel, String postcode) {
		this.email = email;
		this.tel = tel;
		this.postcode = postcode;
	}

	public User(String email, String tel, String postcode, Set certificates,
			Set keyrings) {
		this.email = email;
		this.tel = tel;
		this.postcode = postcode;
		this.certificates = certificates;
		this.keyrings = keyrings;
	}

	public String getEmail() {
		return this.email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getTel() {
		return this.tel;
	}

	public void setTel(String tel) {
		this.tel = tel;
	}

	public String getPostcode() {
		return this.postcode;
	}

	public void setPostcode(String postcode) {
		this.postcode = postcode;
	}

	public Set getCertificates() {
		return this.certificates;
	}

	public void setCertificates(Set certificates) {
		this.certificates = certificates;
	}

	public Set getKeyrings() {
		return this.keyrings;
	}

	public void setKeyrings(Set keyrings) {
		this.keyrings = keyrings;
	}

}
