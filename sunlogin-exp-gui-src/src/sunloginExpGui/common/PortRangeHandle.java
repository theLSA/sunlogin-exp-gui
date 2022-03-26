package sunloginExpGui.common;

import java.util.HashMap;
import java.util.Map;


public class PortRangeHandle {
	public Map<String, Integer> return_min_and_max_port(String portRange){
		
        Map<String, Integer> portMap = new HashMap<String, Integer>();
	
		int startPort = 0;
		int endPort = 65535;

		if(portRange.contains("-")) {
			
			startPort = Integer.valueOf(portRange.split("-")[0]).intValue();
			endPort = Integer.valueOf(portRange.split("-")[1]).intValue();
			
		}
		else {
			
			startPort = endPort = Integer.valueOf(portRange).intValue();
			
		}
		
		portMap.put("startPort", startPort);
		portMap.put("endPort", endPort);
		return portMap;
		
	}
}
