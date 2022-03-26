package sunloginExpGui.portscan;


import java.util.ArrayList;



import sunloginExpGui.mainJFrame.SunloginExpGui;


public class PortscanBySocketCallFunction {
	
	ArrayList<String> TargetIpList;
	int threads;
	int portscanTimeout;
	int startPort;
	int endPort;
	
	public PortscanBySocketCallFunction(ArrayList<String> TargetIpList,int threads,int httpTimeout,int startPort,int endPort) {
		this.TargetIpList = TargetIpList;
		this.threads = threads;
		this.portscanTimeout = httpTimeout;
		this.startPort = startPort;
		this.endPort = endPort;
	}
	
	public static ArrayList<String> returnIpWithSunloginVulnApiPortList = new ArrayList<String>();
	
	public void portscan_by_socket_call_function() {
		SunloginExpGui.portscanTextArea.setText("Starting port scan......\n");
		
		long startTime = System.currentTimeMillis();
		
		//ArrayList<String> returnIpWithSunloginVulnApiPortList = new ArrayList<String>();
		
		if(SunloginExpGui.checkAliveIpBox.isSelected()) {
			SunloginExpGui.portscanTextArea.append("Checking alive ip......\n");
			CheckHostAlive cha = new CheckHostAlive(portscanTimeout, threads);
			TargetIpList = cha.check_host_alive_by_icmp(TargetIpList);
			//for(int aliveIpIndex=0;aliveIpIndex<TargetIpList.size();aliveIpIndex++) {
			//	SunloginExpGui.portscanTextArea.append(TargetIpList.get(aliveIpIndex));
			//}
			
			System.out.println("alive ip num: " + TargetIpList.size());
			SunloginExpGui.portscanTextArea.append("Checked alive ip over, alive ip num: " + TargetIpList.size() + "\nNow scanning port......\n");
			SunloginExpGui.portscanTextArea.selectAll();
		}
		
		PortscanBySocket psbs = new PortscanBySocket(TargetIpList,startPort,endPort,threads,portscanTimeout);
		returnIpWithSunloginVulnApiPortList = psbs.startPortscanBySocket();
		
		for(int ipWithPortIndex=0;ipWithPortIndex<returnIpWithSunloginVulnApiPortList.size();ipWithPortIndex++) {
			System.out.println(returnIpWithSunloginVulnApiPortList.get(ipWithPortIndex));
			SunloginExpGui.portscanTextArea.append(returnIpWithSunloginVulnApiPortList.get(ipWithPortIndex) + "\n");
			SunloginExpGui.portscanTextArea.selectAll();
		}
		
		long totalTime = System.currentTimeMillis() - startTime;
		
		SunloginExpGui.portscanTextArea.append("Portscan over ! Found " + returnIpWithSunloginVulnApiPortList.size() + " vulnerable !! (Total " + (totalTime/(1000.0)) +  " seconds.)\n");
		System.out.println("total: " + (totalTime/(1000.0)) +  "seconds.");
		SunloginExpGui.portscanTextArea.selectAll();
		
		SunloginExpGui.portscanProgressLabel.setText("portscan over!!!");
	}
}
