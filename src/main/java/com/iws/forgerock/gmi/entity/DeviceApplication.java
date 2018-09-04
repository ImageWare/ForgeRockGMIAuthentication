/** 
 * File:    Device.java
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
 * May 11, 2014 - Pete Byhre : Created
 * 
 * 
 */

package com.iws.forgerock.gmi.entity;

import java.io.IOException;

import javax.validation.constraints.Pattern;
import javax.xml.bind.annotation.XmlRootElement;

//import org.hibernate.validator.constraints.Length;
//import org.hibernate.validator.constraints.NotBlank;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;



/**
 *
 */
@XmlRootElement
public class DeviceApplication
{
	public DeviceApplication()
	{
		
	}
	
	public static DeviceApplication parseJSON(String json) throws JsonParseException, JsonMappingException, IOException
	{
		ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        return  mapper.readValue(json, DeviceApplication.class);
	}
	
	public DeviceApplication(String id)
	{
		setDeviceId(id);
	}

	public String getDeviceId()
	{
		return deviceId;
	}
	
	public void setDeviceId(String id)
	{
		deviceId = id;
	}
	
	public String getPlatform()
	{
		return platform;
	}
	
	public void setPlatform(String p)
	{
		platform = p;
	}
	
	public String getPlatformVersion()
	{
		return platformVersion;
	}
	
	public void setPlatformVersion(String version)
	{
		platformVersion = version;
	}
	
	public String getClientVersion()
	{
		return clientVersion;
	}
	
	public void setClientVersion(String version)
	{
		clientVersion = version;
	}
	
	public String getName()
	{
		return name;
	}
	
	public void setName(String n)
	{
		name = n;
	}
	
	public String getPushToken()
	{
		return pushToken;
	}
	
	public void setPushToken(String push_token)
	{
		pushToken = push_token;
	}
	
	public String getApplicationCode()
	{
		return applicationCode;
	}
	
	public void setApplicationCode(String code)
	{
		applicationCode = code;
	}
	
	public void setApplicationVersion(String version)
	{
		applicationVersion = version;
	}
	
	public String getApplicationVersion()
	{
		return applicationVersion;
	}
	
	public void setPublicKey(String key)
	{
		publicKey = key;
	}
	
	public String getPublicKey()
	{
		return publicKey;
	}
	
	@Pattern(regexp="[a-zA-Z0-9_-]{1,255}", message="Invalid value.  Must contain between 1 and 255 letters, numbers, _ -")
	private String	deviceId = null;
	
	//@NotBlank
	@Pattern(regexp="ios|android|IOS|ANDROID", message="Invalid value.  Must be 'ios' or 'android' or 'IOS' or 'ANDROID'")
	private String	platform = null;
	
	//@Length(min=0, max=45)
	private String	name = null;
		
	//@NotBlank
	@Pattern(regexp="[a-zA-Z0-9._-]{1,255}", message="Invalid value.  Must contain between 1 and 255 letters, numbers, and . - _")
	private String	platformVersion = null;
	
	//@Length(max=255)
	private String	pushToken = null;

	//@NotBlank
	@Pattern(regexp="[a-zA-Z0-9._-]{1,255}", message="Invalid value.  Must contain between 1 and 255 letters, numbers, and . - _")
	private String	clientVersion = null;
	
	private String applicationCode;
	
	private String applicationVersion;
	
	private String publicKey;
}
