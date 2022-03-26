package sunloginExpGui.common;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.JFileChooser;

public class Exporter {
	public void export_portscan_result(ArrayList<String> returnIpWithSunloginVulnApiPortList) {
		JFileChooser fc = new JFileChooser();
		int ssd = fc.showSaveDialog(null);
		if(0 == ssd) {
			File saveFile = fc.getSelectedFile();
			//String[] sp = s.split("[\\r\\n]");
		
			try {
				FileWriter writeout = new FileWriter(saveFile);
				for(int IpWithSunloginVulnApiPortIndex=0; IpWithSunloginVulnApiPortIndex<returnIpWithSunloginVulnApiPortList.size(); IpWithSunloginVulnApiPortIndex++) {
					writeout.write(returnIpWithSunloginVulnApiPortList.get(IpWithSunloginVulnApiPortIndex));
            		writeout.write("\r\n");
            	}
				
				writeout.close();
			}catch(IOException ex) {
				ex.printStackTrace();
			}
			
		}else {
			return;
		}
	}
}
