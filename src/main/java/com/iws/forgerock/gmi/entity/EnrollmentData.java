/** 
 * File:    EnrollmentData.java
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
 * Jul 24, 2014 - Pete Byhre : Created
 * 
 * 
 */
package com.iws.forgerock.gmi.entity;

import java.util.Date;

/**
 * @author pbyhre
 *
 */
public class EnrollmentData
{
	public EnrollmentData()
	{
		
	}
	
	public EnrollmentData(int bio_type, Date enroll_timestamp)
	{
		setBioType(bio_type);
		setEnrollTimestamp(enroll_timestamp);
	}
	
	public String getTenantCode()
	{
		return m_tenant_code;
	}

	public void setTenantCode(String tenant_code)
	{
		m_tenant_code = tenant_code;
	}

	public String getCaptureType()
	{
		return m_capture_type;
	}

	public void setCaptureType(String capture_type)
	{
		m_capture_type = capture_type;
	}
	
	public void setBioType(int bio_type)
	{
		m_bio_type = bio_type;
	}
	
	public int getBioType()
	{
		return m_bio_type;
	}
	
	public void setEnrollTimestamp(Date timestamp)
	{
		m_enroll_timestamp = timestamp;
	}
	
	public Date getEnrollTimestamp()
	{
	    return m_enroll_timestamp;
	}
	
	private String m_tenant_code = null;
	private String m_capture_type = null;
	private int	m_bio_type = 0;
	private Date m_enroll_timestamp = null;
}
