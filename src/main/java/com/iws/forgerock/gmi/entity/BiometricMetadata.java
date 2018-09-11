/** 
 * File:    BiometricMetadata.java
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
 * Jul 23, 2014 - Pete Byhre : Created
 * 
 * 
 */
package com.iws.forgerock.gmi.entity;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.TimeZone;

/**
 * @author pbyhre
 *
 */
public class BiometricMetadata
{
	public BiometricMetadata()
	{
		
	}
	
	public void saveEnrollmentData(int bio_type, Date enroll_timestamp)
	{
		if (m_enrollment_data == null)
		{
			m_enrollment_data = new ArrayList<EnrollmentData>();
		}
		
		for (EnrollmentData data : m_enrollment_data)
		{
			if (data.getBioType() == bio_type)
			{
				data.setEnrollTimestamp(enroll_timestamp);
				return;
			}
		}
		// if we get here, we did not find an EnrollmentData for this bio type.  need to add one
		m_enrollment_data.add(new EnrollmentData(bio_type, enroll_timestamp));
	}
	
	public void setEnrollmentData(List<EnrollmentData> data)
	{
		m_enrollment_data = new ArrayList<EnrollmentData>(data);
	}

	public List<EnrollmentData> getEnrollmentData()
	{
		return m_enrollment_data;
	}
	


	private List<EnrollmentData> m_enrollment_data = null;
	
}
