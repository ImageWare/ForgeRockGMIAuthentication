package com.iws.forgerock;

import javax.validation.constraints.Pattern;
import javax.xml.bind.annotation.XmlRootElement;


/**
 *
 */
@XmlRootElement
public class Application
{
	public final static int MAX_CODE_LENGTH = 45;
	
	
	public Application()
	{
		
	}
	
	public Application(String code)
	{
		setCode(code);
	}
	
	public String getCode()
	{
		return code;
	}
	
	public void setCode(String code)
	{
		this.code = code;
	}
	
	public String getName()
	{
		return name;
	}
	
	public void setName(String name)
	{
		this.name = name;
	}
	
	public String getGcmKey()
	{
		return gcmKey;
	}
	
	public void setGcmKey(String gcm_key)
	{
		this.gcmKey = gcm_key;
	}
	
	public String getApnsCertificatePassword()
	{
		return apnsCertificatePassword;
	}
	
	public void setApnsCertificatePassword(String password)
	{
		this.apnsCertificatePassword = password;
	}
	
	public byte[] getApnsCertificate()
	{
		return apnsCertificate;
	}
	
	public void setApnsCertificate(byte[] cert)
	{
		this.apnsCertificate = cert;
	}
	
	public byte[] getApnsCertificateTest()
	{
		return apnsCertificateTest;
	}
	
	public void setApnsCertificateTest(byte[] cert_test)
	{
		this.apnsCertificateTest = cert_test;
	}
	
	public String getEnvironment()
	{
		return environment;
	}

	public void setEnvironment(String environment)
	{
		this.environment = environment;
	}
	
	public String getAlertSound()
	{
		return alertSound;
	}

	public void setAlertSound(String alert_sound)
	{
		this.alertSound = alert_sound;
	}
	
	public String getAlertText()
	{
		return alertText;
	}

	public void setAlertText(String alertText)
	{
		this.alertText = alertText;
	}

	public void setValidationType(String validationType)
	{
		this.validationType = validationType;
	}
	
	public String getValidationType()
	{
		return validationType;
	}

	public void setValidationInfo(String validationInfo)
	{
		this.validationInfo = validationInfo;
	}
	
	public String getValidationInfo()
	{
		return validationInfo;
	}

	public void setValidationSuccessInfo(String validationSuccessInfo)
	{
		this.validationSuccessInfo = validationSuccessInfo;
	}
	
	public String getValidationSuccessInfo()
	{
		return validationSuccessInfo;
	}

	public void setValidationFailInfo(String validationFailInfo)
	{
		this.validationFailInfo = validationFailInfo;
	}
	
	public String getValidationFailInfo()
	{
		return validationFailInfo;
	}

	public void setValidationFromAlias(String validationFromAlias)
	{
		this.validationFromAlias = validationFromAlias;
	}
	
	public String getValidationFromAlias()
	{
		return validationFromAlias;
	}

	//@Length(min=0, max=45)
	@Pattern(regexp="[a-zA-Z0-9]{1,255}", message="Invalid value.  Must contain between 1 and 255 letters, and numbers")
	private String	code = null;
	@Pattern(regexp="[\\x20a-zA-Z0-9.,_-\u2122\u00AE]{1,255}", message="Invalid value.  Must contain between 1 and 255 letters, numbers, and . , - _ \u2122 \u00AE")
	private String	name = null;
	@Pattern(regexp="[a-zA-Z0-9.,_-]{1,255}", message="Invalid value.  Must contain between 1 and 255 letters, numbers, and . , - _")
	private	String	gcmKey	= null;
	private String	apnsCertificatePassword	= null;
	private byte[]	apnsCertificate = null;
	private byte[]	apnsCertificateTest = null;
	private String	environment;
	//@Length(min=0, max=255)
	private String	alertSound = null;
	//@Length(min=0, max=255)
	private String	alertText = null;
	
	@Pattern(regexp="email|tenant")
	private String validationType="email";
	private String validationInfo="";
	private String validationSuccessInfo="";
	private String validationFailInfo="";
	private String validationFromAlias="";
}
