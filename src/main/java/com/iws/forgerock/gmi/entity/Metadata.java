/** 
 * File:    Metadata.java
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


/**
 * @author pbyhre
 *
 */
public class Metadata
{
	public void setBiometricMetadata(BiometricMetadata bio)
	{
		m_biometric_metadata = bio;
	}
	
	public BiometricMetadata getBiometricMetadata()
	{
		return m_biometric_metadata;
	}
	
	
	private BiometricMetadata m_biometric_metadata = null;
}