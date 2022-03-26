package sunloginExpGui.common;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;

public class InputCheck {
	//check ip/domain format
	public String check_ip_or_domain_format(String input) {
		
		//check ip format
		//String ipFormatRegex = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
	    //return Pattern.matches(ipFormatRegex, input); 
	    
	    //check domain format
        //String domainFormatRegex = "^(?!-)(?!.*?-$)[-a-zA-Z0-9\\u4e00-\\u9fa5]*$";
        //return Pattern.matches(domainFormatRegex, input);
        
		HostName domainOrIp = new HostName(input);
		try {
			domainOrIp.validate();
			if(domainOrIp.isAddress()) {
				//System.out.println("ip: " + domainOrIp.asAddress());
				return "isIp";
			} else {
				//System.out.println("domain: " + domainOrIp);
				return "isDomain";
			}
		} catch(HostNameException e) {
			System.out.println(e.getMessage());
			return "hostNameException";
		}
		/*
        if (Pattern.matches(ipFormatRegex, input) || Pattern.matches(domainFormatRegex, input)) {
        	return true;
        }
        else {
        	return false;
        }*/
        
	}
	
	public boolean check_port_range(String input) {
		
		String int1;
		String int2;
		
		int int1ToInt;
		int int2ToInt;
		
		int int0;
		
		if(input.contains("-")) {
			int1 = input.split("-")[0];
			int2 = input.split("-")[1];
			
			Pattern p0 = Pattern.compile("[0-9]*");
			Matcher isInt1 = p0.matcher(int1);
			Matcher isInt2 = p0.matcher(int2);
			
			if(!isInt1.matches() && !isInt2.matches()) {
				System.out.println("port range format invaild, please input a int or int1-int2");
				return false;
			}
			else {
				
				int1ToInt = Integer.valueOf(int1).intValue();
				int2ToInt = Integer.valueOf(int2).intValue();
				
				if(int1ToInt<=65535 && int1ToInt>=0 && int2ToInt<=65535 && int2ToInt>=0 && int1ToInt<int2ToInt) {
					return true;
				}
				else {
					System.out.println("port range format invaild, please input a int or int1-int2");
					return false;
				}
			}
			
			
		}
		else {
			
			Pattern p1 = Pattern.compile("[0-9]*");
			Matcher isInt0 = p1.matcher(input);
			
			if(!isInt0.matches()) {
				System.out.println("port range format invaild, please input a int or int1-int2");
				return false;
			}
			else {
				int0 = Integer.valueOf(input).intValue();
				if(int0<=65535 && int0>=0) {
					return true;
				}
				else {
					System.out.println("port range format invaild, please input a int or int1-int2");
					return false;
				}
			}
		
		}
	}
	
	
	
	
	//check url format
	public boolean check_url_format(String input) {
		String regex = "(https?://(w{3}\\.)?)?\\w+\\.\\w+(\\.[a-zA-Z]+)*(:\\d{1,5})?(/\\w*)*(\\??(.+=.*)?(&.+=.*)?)?"; 
	    return Pattern.matches(regex, input); 
	}
}
