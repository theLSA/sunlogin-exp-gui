package sunloginExpGui.common;

import java.net.UnknownHostException;
import java.util.ArrayList;

import inet.ipaddr.HostName;
import inet.ipaddr.HostNameException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import sunloginExpGui.mainJFrame.SunloginExpGui;

public class TargetIpOrDomainHandle {
	public ArrayList<String> returnTargetIpList(){
		
		String domainOrIp = SunloginExpGui.targetFiled.getText().trim();
		
		InputCheck ic0 = new InputCheck();
		String checkTargetFieldInput = ic0.check_ip_or_domain_format(domainOrIp);
		
		ArrayList<String> TargetIpList = new ArrayList<String>();		
		
		if(checkTargetFieldInput == "isIp") {
			
			IPAddressString ipAddressString = new IPAddressString(domainOrIp);
			IPAddress address = ipAddressString.getAddress();
			
			System.out.println("IP count: " + address.getCount());
			SunloginExpGui.portscanTextArea.append("IP count: " + address.getCount() + "\n");
			  
			IPAddress ipAddressRange = address.removePrefixLength(false);
			for (IPAddress ipv4AddressIter : ipAddressRange.getIterable()) {
			    //System.out.println(ipv4AddressIter.toCompressedString());
			    TargetIpList.add(ipv4AddressIter.toCompressedString());
			}
			
			
		}
		if(checkTargetFieldInput == "isDomain") {
			try {
				//String dnsStr = "www.baidu.com";
				HostName domainName = new HostName(domainOrIp);
		

				IPAddress domain2ip = domainName.toAddress(); // resolves if necessary
				System.out.println(domain2ip.toString());
				SunloginExpGui.portscanTextArea.append("Domain: " + domainOrIp + "[" + domain2ip.toString() + "]\n");
				// use address
				TargetIpList.add(domain2ip.toString());
			} catch (HostNameException | UnknownHostException e1) {
				String msg = e1.getMessage();
				// handle improperly formatted host name or address string
				System.out.println(msg);
			}
			
		}
		
		
		if(checkTargetFieldInput == "hostNameException") {
			System.out.println("Hostname Exception!!!");
			
		}
		
		return TargetIpList;
	}
}
