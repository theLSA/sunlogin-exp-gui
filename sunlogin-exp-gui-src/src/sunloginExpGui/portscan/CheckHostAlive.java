package sunloginExpGui.portscan;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import sunloginExpGui.mainJFrame.SunloginExpGui;




public class CheckHostAlive {
	
	 	//private final String address;
	    private final int portscanTimeout;
	    private final int threads;
	    
	    ArrayList<String> aliveIpList = new ArrayList<String>();

	    CheckHostAlive(final int portscanTimeout,final int threads)
	    {
	        //this.address = address;
	        this.portscanTimeout = portscanTimeout;
	        this.threads = threads;
	    }

	    
	    public ArrayList<String> check_host_alive_by_icmp(ArrayList<String> TargetIpList) {
	    	
	    	final ExecutorService checkIpAliveES = Executors.newFixedThreadPool(threads);
	    	final List<Future<isReachableResult>> checkIpAliveFutures = new ArrayList<>();
    
	    	for(int targetIpIndex=0;targetIpIndex<TargetIpList.size();targetIpIndex++)
	    	{
	    		checkIpAliveFutures.add(checkIsReachable(TargetIpList.get(targetIpIndex), checkIpAliveES));
	    	}

	    	try
	    	{
	    		checkIpAliveES.shutdown();
	    		//checkIpAliveES.awaitTermination(5, TimeUnit.MILLISECONDS);
	    	} catch (Exception e)
	    	{
	    		System.out.println(e);
	    	}

	    	for (final Future<isReachableResult> ciaf : checkIpAliveFutures)
	    	{
	    		
	    		if(SunloginExpGui.stopPortscanFlag) {   //&& !Thread.currentThread().isInterrupted()
	    			checkIpAliveES.shutdown();
	        		try {       
	        		    if(!checkIpAliveES.awaitTermination(5, TimeUnit.SECONDS)) {
	        		    	List<Runnable> waitRunTasks = checkIpAliveES.shutdownNow();
	        		    	int waitRunTasksListSize = waitRunTasks.size();
	        		    	
	        		    	System.out.println("wait run icmp tasks size is " + waitRunTasksListSize);
	        		    	SunloginExpGui.portscanTextArea.append("wait icmp run tasks size is " + waitRunTasksListSize + "\n");
	        		    }
	        		} catch (InterruptedException e) {
	        			List<Runnable> waitRunTasks = checkIpAliveES.shutdownNow();
	        			int waitRunTasksListSize = waitRunTasks.size();
	        			
	        			System.out.println("wait icmp run tasks size is " + waitRunTasksListSize);
	    		    	SunloginExpGui.portscanTextArea.append("wait icmp run tasks size is " + waitRunTasksListSize + "\n");
	        		}
	        		SunloginExpGui.portscanProgressLabel.setText("Stopped icmp scan.");
	        		break;
	        		
	        	}

	    		
	    		try
	    		{
	    			if (ciaf.get().isReachable())
	    			{
	    				System.out.println(ciaf.get().ipAddress + " is rechable!\n");
	    				aliveIpList.add(ciaf.get().ipAddress);
	    				SunloginExpGui.portscanTextArea.append(ciaf.get().ipAddress + "\n");
	    				SunloginExpGui.portscanTextArea.selectAll();
	    			}
	    		} catch (Exception e)
	    		{
	    			System.out.println(e);
	    		}
	    	}
	    	
	    	
	    	
	    	SunloginExpGui.portscanProgressLabel.setText("Check alive ip over!");
	    	return aliveIpList;
	
	    }
	    
	/*
	public ArrayList<String> check_host_alive_by_icmp(ArrayList<String> TargetIpList, int threads, int portscanTimeout) {
		
		ArrayList<String> aliveIpList = new ArrayList<String>();
		
		long startTime = System.currentTimeMillis();     //starting time
        
        //  starting scanning port .
		//System.out.println("Checking ip alive : "+ ip + "...");
		//SunloginExpGui.portscanTextArea.append("Checking ip alive: "+ ip + ".......................................\n");
    
		final ExecutorService checkIpAliveES = Executors.newFixedThreadPool(threads);   //run 20 threads. 
    
		//final List<Future<portscanResult>> futures = new ArrayList<>();
		List<Callable<String>> checkIpTaskList = new ArrayList<Callable<String>>();
		
		//final String checkIp = "";
		Callable<String> callableObj = () -> {
			
			return checkIp;
			
		};
    
		for(int targetIpIndex=0;targetIpIndex<TargetIpList.size();targetIpIndex++)
		{
			//checkIp = TargetIpList.get(targetIpIndex);
			//futures.add(portscanTaskSocketMethod(es, ip, nowPort));   //or List<Future<String>> futures = executorService.invokeAll(callableTasks);
			checkIpTaskList.add(callableObj);
		}
		
		
		try {
			List<Future<String>> futures = checkIpAliveES.invokeAll(checkIpTaskList);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		
		return TargetIpList;
		
	
	
	}
	*/
	    public class isReachableResult
	    {
	        private final String ipAddress;
	        private final boolean isReachable;
	        private final String hostName;

	        isReachableResult(final String ipAddress, final boolean isReachable, final String hostname)
	        {
	            this.ipAddress = ipAddress;
	            this.isReachable = isReachable;
	            this.hostName = hostname;
	        }

	        public String getIPAddress() { return ipAddress; }
	        public boolean isReachable() { return isReachable; }
	        public String getHostname() { return hostName; }
	    }
	    
	    public Future<isReachableResult> checkIsReachable(String address, final ExecutorService checkIpAliveES)
	    {
	        return checkIpAliveES.submit(() -> {
	            try
	            {
	            	SunloginExpGui.portscanProgressLabel.setText("Checking alive: " + address);
	                String hostName = null;
	                boolean result = InetAddress.getByName(address).isReachable(portscanTimeout);
	                if (result)
	                {
	                	hostName = InetAddress.getByName(address).getHostName();
	                }
	                return new isReachableResult(address, result, hostName);
	            } catch (UnknownHostException e) {
					// TODO: handle exception
	            	return new isReachableResult(address, false, null);
				} catch (IOException e)
	            {
	                return new isReachableResult(address, false, null);
	            }
	        });
	    }
}
