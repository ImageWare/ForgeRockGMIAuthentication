/**
 * File:    Person.java
 * Package: com.iwsinc.gmiserver.entity
 *
 * Copyright (c) 2014 ImageWare Systems, Inc.
 * http://www.iwsinc.com
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of ImageWare Systems, Inc.
 * ("Confidential Information").  You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with ImageWare Systems, Inc..
 *
 *
 *
 * Change History:
 * Date - Who : Details
 * --------------------------------------------------------------------
 * May 6, 2014 - Pete Byhre : Created
 *
 *
 */

package com.iws.forgerock;

import javax.validation.constraints.Pattern;



/**
 *
 */
public class Person
{
	public static final String BIOMETRIC_METADATA = "biometricMetadata";

	public Person()
	{
	}

	public Person(String uuid)
	{
		setId(uuid);
	}

	public String getId()
	{
		return m_id;
	}

	public void setId(String uuid)
	{
		m_id = uuid;
	}

	public String getUserId()
	{
		return m_user_id;
	}

	public void setUserId(String user_id)
	{
		m_user_id = user_id;
	}

	public String getEnrollServer()
	{
		return m_enroll_server;
	}

	public void setEnrollServer(String enroll_server)
	{
		m_enroll_server = enroll_server;
	}

	public String getVerifyServer()
	{
		return m_verify_server;
	}

	public void setVerifyServer(String verify_server)
	{
		m_verify_server = verify_server;
	}


	public String getTenantEnrollServer()
	{
		return m_tenant_enroll_server;
	}

	public void setTenantEnrollServer(String tenant_enroll_server)
	{
		m_tenant_enroll_server = tenant_enroll_server;
	}

	public String getTenantVerifyServer()
	{
		return m_tenant_verify_server;
	}

	public void setTenantVerifyServer(String tenant_verify_server)
	{
		m_tenant_verify_server = tenant_verify_server;
	}

	public void setVoiceDigits(String voice_digits)
	{
		m_voice_digits = voice_digits;
	}

	public String getVoiceDigits()
	{
		return m_voice_digits;
	}


	private String 		m_id = null;

	@Pattern(regexp="[a-zA-Z0-9'{}|!#$%&^*/=?`~@._+-]{1,255}", message="Invalid value.  Must contain between 1 and 255 letters, numbers, and '{}|!#$%&^*/=?`~@._+-")
	private String		m_user_id = null;

	@Pattern(regexp="[0-9]{7}", message="Invalid value.  Must contain 7 numbers")
	private String 		m_voice_digits = null;
	private String		m_enroll_server = null;
	private String		m_verify_server = null;
	private String		m_tenant_enroll_server = null;
	private String		m_tenant_verify_server = null;

}
