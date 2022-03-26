package sunloginExpGui.portscan;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import sunloginExpGui.exploit.GetSunloginInfo;
import sunloginExpGui.mainJFrame.SunloginExpGui;





public class PortscanBySocket {
	
	 //static int checkedPortCount = 0;
	 
	 
	 int startPort;
	 int endPort;
	 int threads;
	 int portscanTimeout;
	 ArrayList<String> ipList = new ArrayList<String>();
	 
	 ArrayList<String> ipWithSunloginVulnApiPortList = new ArrayList<String>();
	
	public PortscanBySocket(ArrayList<String> ipList,int startPort,int endPort,int threads,int portscanTimeout) {
		this.startPort = startPort;
		this.endPort = endPort;
		this.ipList = ipList;
		this.threads = threads;
		this.portscanTimeout = portscanTimeout;
	}

	public ArrayList<String> startPortscanBySocket() {
		// TODO Auto-generated method stub

		/*
		ArrayList<String> ipList = new ArrayList<String>();
		
		ipList.add("");
		ipList.add("");
		ipList.add("");
        //sites.add("");
        
        */
		
		SunloginExpGui.stopPortscanFlag = false;
		
		
		for(int ipIndex=0;ipIndex<ipList.size();ipIndex++) {
			
			if(SunloginExpGui.stopPortscanFlag) {
				SunloginExpGui.portscanTextArea.append("Stopped !\n");
				SunloginExpGui.portscanProgressLabel.setText("Stopped all portscan.");
				break;
			}
			
			portscanSocketMethod(ipList.get(ipIndex));
		}
	        
	    return ipWithSunloginVulnApiPortList;
	}

	
	
	public void portscanSocketMethod(String ip) {
		//int start = 10;
	      
        //int end = 1000;

        int theOpenPort;
        //checkedPortCount = 0;
        int checkedPortCount = 0;
        
        String ipWithSunloginVulnApiPort;

        long startTime = System.currentTimeMillis();     //starting time
        
            //  starting scanning port .
        System.out.println("Scanning ip : "+ ip + "...");
        SunloginExpGui.portscanTextArea.append("Scanning ip : "+ ip + ".......................................\n");
        
        final ExecutorService es = Executors.newFixedThreadPool(threads);   //run 20 threads. 
        
        final List<Future<portscanResult>> futures = new ArrayList<>();
        
        for(int nowPort=startPort; nowPort<=endPort; nowPort++)
        {

        	futures.add(portscanTaskSocketMethod(es, ip, nowPort));   //or List<Future<String>> futures = executorService.invokeAll(callableTasks);
        	
        }
        
        es.shutdown();
        
        for(final Future<portscanResult> fs : futures)
        {
        	
        	if(SunloginExpGui.stopPortscanFlag) {   //&& !Thread.currentThread().isInterrupted()
        		es.shutdown();
        		try {       
        		    if(!es.awaitTermination(5, TimeUnit.SECONDS)) {
        		    	List<Runnable> waitRunTasks = es.shutdownNow();
        		    	int waitRunTasksListSize = waitRunTasks.size();
        		    	System.out.println("wait run tasks size is " + waitRunTasksListSize);
        		    	SunloginExpGui.portscanTextArea.append("wait run tasks size is " + waitRunTasksListSize + "\n");
        		    }
        		} catch (InterruptedException e) {
        			List<Runnable> waitRunTasks = es.shutdownNow();
        			int waitRunTasksListSize = waitRunTasks.size();
        			System.out.println("wait run tasks size is " + waitRunTasksListSize);

    		    	SunloginExpGui.portscanTextArea.append("wait run tasks size is " + waitRunTasksListSize + "\n");
        		}
        		SunloginExpGui.portscanProgressLabel.setText("Stopped portscan.");
        		break;
        		
        	}
        	
        	
        	
            try {
				if(fs.get().portStatus())   //or get(long timeout, TimeUnit unit)
				{
					theOpenPort = fs.get().returnPortNum();
				    System.out.println(theOpenPort);
				    //openPorts++;
				 
				    if(fs.get().foundSunloginVulnApiPort) {
				    //if(theOpenPort==443) {

				    	ipWithSunloginVulnApiPort = ip+":"+theOpenPort;
				    	
				    	ipWithSunloginVulnApiPortList.add(ipWithSunloginVulnApiPort);
				    	
				    	System.out.println("Found the sunlogin vuln api port !!! Now break.");
				    	
				    	SunloginExpGui.portscanTextArea.append("Found the sunlogin vuln api port:[" + ipWithSunloginVulnApiPort + "]\n");
				    	SunloginExpGui.portscanTextArea.selectAll();
				    	
				    	es.shutdownNow();
				    	break;
				    }
				}
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            checkedPortCount++;
        }
        
        
        
        long totalTime = System.currentTimeMillis() - startTime;
        
        System.out.println("Done. checked/Total " + checkedPortCount + "/" + (endPort-startPort+1) + " ports in " + (totalTime/(1000.0)) + " seconds.");
        SunloginExpGui.portscanTextArea.append("Done. checked/Total " + checkedPortCount + "/" + (endPort-startPort+1) + " ports in " + (totalTime/(1000.0)) + " seconds.\n");
        SunloginExpGui.portscanTextArea.selectAll();
	
	}
	
	public static class portscanResult
    {
        private final int checkedPort ;
        private final boolean isOpenPort ;
        private boolean foundSunloginVulnApiPort = false;
        
        portscanResult(int cp, boolean iop, boolean fslvap)
        {
            this.checkedPort = cp;
            this.isOpenPort = iop;
            this.foundSunloginVulnApiPort = fslvap;
        }
        
        public int returnPortNum()
        {
            return this.checkedPort;
        }
        
        public boolean portStatus()
        {
            return this.isOpenPort ;
        }
    }
	
	 public Future<portscanResult> portscanTaskSocketMethod(final ExecutorService es, String ip, int port)
	    {
	        return es.submit(new Callable<portscanResult>()   //or labeda expr
	        {
	            @Override
	            public portscanResult call()
	            {
	            	//checkedPortCount++;
	            	portscanResult psr = new portscanResult(port, false, false);
	                //long strT = System.currentTimeMillis() ;
	                
	                try
	                {
	                	SunloginExpGui.portscanProgressLabel.setText("Portscan: " + ip + ":" + port);
	                	
	                    Socket s0 = new Socket();
	                    
	                    s0.connect(new InetSocketAddress(ip,port), portscanTimeout);
	                    
	                    s0.close();         
	                    
	                    psr = new portscanResult(port, true, false);
              
	                    /*
	                    if(port==443) {
	                    	psr.foundSunloginVulnApiPort = true;
	                    	//es.shutdownNow();
	                    }
	                    */
	                    
	                    int httpTimeout = Integer.valueOf(SunloginExpGui.attackTimeoutField.getText().trim()).intValue();
	                    GetSunloginInfo gpf = new GetSunloginInfo(ip+":"+port,httpTimeout);
	                    
	                    
	                    if(gpf.get_sunlogin_vuln_api_port()) {
	                    	psr.foundSunloginVulnApiPort = true;
	                    }
	                    
	                    
	                    return psr;

	                    /*
	                    if(port==80) {
	                    	
	                    	okFlag = true;
	                    
	                    	rl = new result(port , true);
                          	
	                    	//es.shutdownNow();
	                    
	                    	return rl;
	                    }
	                    
	                    else {
        
	                    	return rl;
	                    }*/
	                    
	                }
	                catch(Exception e)
	                {
	                	//psr.foundSunloginVulnApiPort = false;
	                    return psr ;
	                }
	            }
	        }  );
	    }
}
