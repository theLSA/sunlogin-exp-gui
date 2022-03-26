package sunloginExpGui.portscan;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import sunloginExpGui.exploit.GetSunloginInfo;
import sunloginExpGui.mainJFrame.SunloginExpGui;

public class PortscanByNmap {
	
	public String nmapDir;
	public String nmapCommand;
	
	public static ArrayList<String> returnIpWithSunloginVulnApiPortList = new ArrayList<String>();
	
	public PortscanByNmap(String nmapDir,String nmapCommand) {
		this.nmapDir = nmapDir;
		this.nmapCommand = nmapCommand;
	}
	
	public void start_portscan_by_nmap(String nmapTarget){
		Process nmapProcess = null;
		StringBuffer stringBuffer = new StringBuffer();
		String nmapResult = "";
		
		try {
			
			System.out.println("Starting nmap......");
			
			nmapProcess = Runtime.getRuntime().exec(nmapDir + nmapCommand + " " + nmapTarget);
			
			SunloginExpGui.portscanProgressLabel.setText("Using nmap to scan port......");
			
			BufferedReader reader = new BufferedReader(new InputStreamReader(nmapProcess.getInputStream(),"UTF-8"));
			String line = null;			
			while((line = reader.readLine()) != null){
				stringBuffer.append(line + "\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		//return stringBuffer.toString();
		nmapResult = stringBuffer.toString();
		System.out.println("nmapResult: "+nmapResult);
		
		SunloginExpGui.portscanProgressLabel.setText("Checking the open port fingerprint......");
		match_nmap_result_open_port(nmapResult);
		SunloginExpGui.portscanProgressLabel.setText("nmap scan over!");
		
	}
	
	
	public void match_nmap_result_open_port(String nmapResult) {
		//Pattern openPortPattern = Pattern.compile("(.*?)/tcp[ ]+open");
		//Pattern openPortPattern = Pattern.compile("([\\d]+)/tcp open");
		//Matcher openPortMatcher = openPortPattern.matcher(nmapResult);
		ArrayList<String> nmapResultIpWithPortList = new ArrayList<String>();
		String nmapResultIpMatcherString = null;
		
		String[] s1 = nmapResult.split("Nmap scan report for");
		
		for(int i=0;i<s1.length;i++) {
			System.out.println(s1[i]);
		
			Pattern nmapResultIpPattern = Pattern.compile(" (\\d+.\\d+.\\d+.\\d+)");
			//Pattern openPortPattern = Pattern.compile("([\\d]+)/tcp open");
			Matcher nmapResultIpMatcher = nmapResultIpPattern.matcher(s1[i]);
		
			if(nmapResultIpMatcher.find()) {
				//nmapOpenPortCount++;
				nmapResultIpMatcherString = nmapResultIpMatcher.group(1);
				System.out.println("nmapResultIpMatcherString: " + nmapResultIpMatcherString);
			}
		
			Pattern openPortPattern = Pattern.compile("(.*?)/tcp[ ]+open");
			//Pattern openPortPattern = Pattern.compile("([\\d]+)/tcp open");
			Matcher openPortMatcher = openPortPattern.matcher(s1[i]);
		
			int nmapOpenPortCount = 0;
		
			while(openPortMatcher.find()) {
				nmapOpenPortCount++;
				String nmapResultOpenPort = openPortMatcher.group(1);
				System.out.println("nmapResultOpenPort: " + nmapResultOpenPort);
				nmapResultIpWithPortList.add(nmapResultIpMatcherString+":"+nmapResultOpenPort);
			}
		
			System.out.println("nmap scanned open port count: " + nmapOpenPortCount);
		}
		
		int httpTimeout = Integer.valueOf(SunloginExpGui.attackTimeoutField.getText().trim()).intValue();
		
		String ipWithPort = "";
		
		for(int nriwpl=0;nriwpl<nmapResultIpWithPortList.size();nriwpl++) {
			ipWithPort = nmapResultIpWithPortList.get(nriwpl);
			System.out.println("ipWithPort: " + ipWithPort);
			
			GetSunloginInfo gsi = new GetSunloginInfo(ipWithPort,httpTimeout);
			if(gsi.get_sunlogin_vuln_api_port()) {
				returnIpWithSunloginVulnApiPortList.add(ipWithPort);
			}
		}
		
		if(returnIpWithSunloginVulnApiPortList.isEmpty()) {
			SunloginExpGui.portscanTextArea.append("\nDone. Found 0 vulnerable.\n");
			SunloginExpGui.portscanTextArea.selectAll();
		}
		
		else {
			SunloginExpGui.portscanTextArea.append("\nFound " + returnIpWithSunloginVulnApiPortList.size() + " vulnerable!!!\n");
			for(int ipWithPortIndex=0;ipWithPortIndex<returnIpWithSunloginVulnApiPortList.size();ipWithPortIndex++) {
				System.out.println(returnIpWithSunloginVulnApiPortList.get(ipWithPortIndex));
				SunloginExpGui.portscanTextArea.append(returnIpWithSunloginVulnApiPortList.get(ipWithPortIndex) + "\n");
				SunloginExpGui.portscanTextArea.selectAll();
			}
		}

	
	}

	/*
	public void check_sunlogin_vuln_api_port_fingerprint_with_nmap_open_port() {
		
	}
	*/
	
	
	public void start_portscan_by_nmap_call_function(String nmapTarget) {
		/*
		for(int targetIpIndex=0; targetIpIndex<TargetIpList.size(); targetIpIndex++) {
			start_portscan_by_nmap(TargetIpList.get(targetIpIndex));
		}
		*/
		start_portscan_by_nmap(nmapTarget);
		
	}
	
	
}
