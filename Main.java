package mk2;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.MathContext;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

public class Main {
//file locations of data
	static String botnetAttackFLowData ="F:\\FYP\\FYP attack results\\flow_results\\Feb\\12\\12-24-33 flow result.csv";
	static String normalTraffic = "F:\\FYP\\FYP attack results\\flow_results\\Feb\\14\\lynx search flow\\lynx search flow data.csv";
	static String hulkTraffic = "F:\\FYP\\FYP attack results\\flow_results\\Feb\\hulk-attack.csv";
	static String slowTraffic = "F:\\FYP\\FYP attack results\\flow_results\\Feb\\slowloris.csv";
	static String newsite ="F:\\FYP\\news webpage lookup.csv";
	static String vod = "F:\\FYP\\VOD Capture.csv";
	
	
	
	static ArrayList<String> srcIP = new ArrayList<String>(); //source ip
	static ArrayList<String> dstIP = new ArrayList<String>(); //destination ip
	static ArrayList<Long> inPckts = new ArrayList<Long>(); //in packets
	static ArrayList<Long> inBytes = new ArrayList<Long>(); //in bytes
	static ArrayList<Long> Fswitch = new ArrayList<Long>(); //first switched
	static ArrayList<Long> Lswitch = new ArrayList<Long>(); //lasted switched
	static ArrayList<Long> Sport = new ArrayList<Long>(); //source port
	static ArrayList<Long> Dport = new ArrayList<Long>(); //Destination port
	static ArrayList<String> TCP = new ArrayList<String>(); //TCP flag
	static ArrayList<Long> protocol = new ArrayList<Long>(); //Protocol
	static ArrayList<String> secSrcDst = new ArrayList<String>(); //in packets
	static ArrayList<String> secDstSrc = new ArrayList<String>(); //in packets
	
	static long Normalbyte=0; //
	static long Normaltime=0;
	static long numPorts=0;

	private static long bytesAvg;
	private static long testBytesAvg;
	
	
	
	public static void main(String[] args) {
		
		//below are in different format, compare on own
	//	readNewsite();
	//	resetLists();
	//	readVOD();
		
		
		
	//	readnormaltrafficCSV(); //reads normal flow data
	//	saveDataFromNormalToCompare(); //saves the data from normal flows for future comparision
	//	readUndPrintCSV(); //reads botnet data
		readHulk(); //read data from hulk attack
	//	readSlow();//read data from slowloris
	//	compareResults();
	}

	

	private static void compareResults() {
		// compares data from normal traffic to attack traffic
		long localtime = getDifference(Fswitch, Lswitch);
		 long localpacket = getAvgPacket(inPckts, inBytes);
		 ArrayList<Long> localPort = checkDestPort(Dport);
		 int cntr=0;
		long lp = localPort.size();
		 //testing bytes sizes, if bytes size between 1000 - 1400 ==normal traffic ~ VOD
			//if lower or higher, say 700 - 999 & >1420, possible attack 
		System.out.println("\n\n\n\n\n ------------------------------------------------------------");
		if ( testBytesAvg < bytesAvg) {
			//initially assumming attack
				if (testBytesAvg > 1420) {
					System.out.println("Unusal activity/Possible attack due to high bytes ( >1420, max is 1500 bytes if normal)");	
				}if ( testBytesAvg < 999) {
					System.out.println("Possible attack as bytes avg consistant with attack characteristics "
							+ "	(less then 999 bytes on average)");
				}if ( testBytesAvg < 300) {
					System.out.println("Unusally low bytes detected, could be attack or flow could be idle");
				}
		}else {
			System.out.println("This message is printed if you did not read in Normal traffic flow first and compared it to attack flows.");
			System.out.println("2nd Reason: you could be comparing 2 attack traffic flows without using a baseline ( normal traffic");
		}
		if ( testBytesAvg == bytesAvg) {
			System.out.println("Last traffic flow seemed to be normal traffic, could be Video on Demmand flow");
			System.out.println("Reasoning is that VOD uses a lot of bytes per unit time");
		}if (testBytesAvg >bytesAvg) {
			System.out.println("Error in code, this should be impossible, please check methods setAvgBytes and setTestAvgBytes");
		}
		
		
		System.out.println("\n\n--------------");
		 
		 if (localtime < Normaltime) {
			 System.out.println("Suspected DDoS attack due to high traffic per unit time\n-------------");
			 cntr++;
		 } if (localtime > 125) {
			 System.out.println("Suspected Slowloris type attack, slow time between responese\n-------------");
		 }
		 if ( localpacket < Normalbyte) {
			 System.out.println("Suspected DDoS attack due to high packet count per byte\n-----------------");
			 cntr++;
		 }if ( lp < numPorts && lp <3) { 
			 //compares number of unique ports
			 //theory is that an attack will focus on a specific port while traffic will spread over a few ports
			 System.out.println("Suspected DDoS attack due to limited amount of ports used\n------------------------");
			 cntr++;
		 }
		if(cntr==1) {
			 System.out.println("Prediction of normal traffic/high traffic --no attack\n--------------------");
		 }
		
		
		
		
		 
	}

	

	private static void saveDataFromNormalToCompare() {
			//predicting normal traffic
			//clear all arraylist, save results from all tests and then compare
			Normaltime = getDifference(Fswitch, Lswitch);
			Normalbyte = getAvgPacket(inPckts, inBytes);
				ArrayList<Long> temp = checkDestPort(Dport);
				numPorts = temp.size(); //gets number of unique ports
		System.out.println("base time is: "+Normaltime +"\nBase byte are "+Normalbyte); 
		
		resetLists(); //reset all arraylists to compare against test data
	}

	private static void resetLists() {
		// reset arraylists so normal data does not affect attack data
		srcIP.clear();
		 dstIP.clear();
		inPckts.clear();
		 inBytes.clear();
		 Fswitch.clear();
		Lswitch.clear();
		 Sport.clear();
		 Dport.clear();
		 TCP.clear();
		 protocol.clear();
		 secSrcDst.clear();
		 secDstSrc .clear();
	}

	private static void readHulk() {
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(hulkTraffic));
			String line = null;
			reader.readLine(); //reads first line
			while ((line = reader.readLine()) != null) {
				
				String[] words = line.split(",");
				if (words[13].equals('"')){
						System.out.println("true"); //attempt to remove " from data as it is useless
			}
				srcIP.add(words[0]); //string
				dstIP.add(words[1]); //string
				inPckts.add(new Long(words[4]));
				inBytes.add(new Long(words[5]));
				Fswitch.add(new Long(words[6]));
				Lswitch.add(new Long(words[7]));
				Sport.add(new Long(words[8]));
				Dport.add(new Long(words[9]));
				TCP.add(words[10]); //string
				protocol.add(new Long(words[11]));
				secSrcDst.add(words[12]);
				secDstSrc.add(words[13]); //
				
				}			//uniform size 
		/*	for ( int i=0;i<srcIP.size();i++) {
				System.out.println(srcIP.get(i)+ "\t" + dstIP.get(i) +"\t"+inPckts.get(i)+"\t"+inBytes.get(i)
				+"\t"+Fswitch.get(i) +"\t"+Lswitch.get(i)+"\t"+Sport.get(i) +"\t"+Dport.get(i) 
				+"\t"+TCP.get(i) +"\t"+protocol.get(i) 
				+"\t"+secSrcDst.get(i) +"\t"+secDstSrc.get(i));
				
			}*/
			getStringMedian(srcIP);
			getDifference(Fswitch, Lswitch); //gets time difference
			getAvgPacket(inPckts, inBytes);
			checkDestPort(Dport); //checks to see if a specific port is targetted
			checkSrcPort(Sport);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
		
	

	private static void readSlow() {
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(slowTraffic));
			String line = null;
			reader.readLine(); //reads first line
			while ((line = reader.readLine()) != null) {
				
				String[] words = line.split(",");
				if (words[13].equals('"')){
						System.out.println("true"); //attempt to remove " from data as it is useless
			}
				srcIP.add(words[0]); //string
				dstIP.add(words[1]); //string
				inPckts.add(new Long(words[4]));
				inBytes.add(new Long(words[5]));
				Fswitch.add(new Long(words[6]));
				Lswitch.add(new Long(words[7]));
				Sport.add(new Long(words[8]));
				Dport.add(new Long(words[9]));
				TCP.add(words[10]); //string
				protocol.add(new Long(words[11]));
				secSrcDst.add(words[12]);
				secDstSrc.add(words[13]); //
				
				}			//uniform size 
		/*	for ( int i=0;i<srcIP.size();i++) {
				System.out.println(srcIP.get(i)+ "\t" + dstIP.get(i) +"\t"+inPckts.get(i)+"\t"+inBytes.get(i)
				+"\t"+Fswitch.get(i) +"\t"+Lswitch.get(i)+"\t"+Sport.get(i) +"\t"+Dport.get(i) 
				+"\t"+TCP.get(i) +"\t"+protocol.get(i) 
				+"\t"+secSrcDst.get(i) +"\t"+secDstSrc.get(i));
				
			}*/
			
			getStringMedian(srcIP);
			getDifference(Fswitch, Lswitch); //gets time difference
			getAvgPacket(inPckts, inBytes);
			checkDestPort(Dport); //checks to see if a specific port is targetted
			checkSrcPort(Sport);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	//reads in normal traffic.
	private static void readnormaltrafficCSV() {
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(normalTraffic));
			String line = null;
			reader.readLine(); //reads first line
			while ((line = reader.readLine()) != null) {
				
				String[] words = line.split(",");
				if (words[13].equals('"')){
						System.out.println("true"); //attempt to remove " from data as it is useless
			}
				srcIP.add(words[0]); //string
				dstIP.add(words[1]); //string
				inPckts.add(new Long(words[4]));
				inBytes.add(new Long(words[5]));
				Fswitch.add(new Long(words[6]));
				Lswitch.add(new Long(words[7]));
				Sport.add(new Long(words[8]));
				Dport.add(new Long(words[9]));
				TCP.add(words[10]); //string
				protocol.add(new Long(words[11]));
				secSrcDst.add(words[12]);
				secDstSrc.add(words[13]); //
				
				}			//uniform size 
			/*for ( int i=0;i<srcIP.size();i++) {
				System.out.println(srcIP.get(i)+ "\t" + dstIP.get(i) +"\t"+inPckts.get(i)+"\t"+inBytes.get(i)
				+"\t"+Fswitch.get(i) +"\t"+Lswitch.get(i)+"\t"+Sport.get(i) +"\t"+Dport.get(i) 
				+"\t"+TCP.get(i) +"\t"+protocol.get(i) 
				+"\t"+secSrcDst.get(i) +"\t"+secDstSrc.get(i));
				
			}*/
			
			getStringMedian(srcIP);
			getDifference(Fswitch, Lswitch); //gets time difference
			getAvgPacket(inPckts, inBytes);
			checkDestPort(Dport); //checks to see if a specific port is targetted
			checkSrcPort(Sport);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
		
	

	private static ArrayList<Long> checkSrcPort(ArrayList<Long> sport2) {
		//reusing checkDestPort code as it same formula needed
		ArrayList<Long> countDPort = new ArrayList<Long>();
		ArrayList<Long> countDPort2 = new ArrayList<Long>(); //for duplicant port
		ArrayList<Long> dups = new ArrayList<Long>();
		int duport=0, portcnt=0, httpcounter=0,dnscntr=0;;
		for(int a = 0; a<sport2.size();a++) {
			long currentIP = sport2.get(a);
			if (countDPort.contains(currentIP)) {
					if(countDPort2.contains(currentIP)==false)  {
						countDPort2.add(currentIP);
					}else {
						dups.add(currentIP); //adds extra duplicats to list for further analysis
					}
					
				duport++;
			}else {
				countDPort.add(currentIP);
			portcnt++;	
			}
		
	}
		for(long e: dups) {
			if (e == 80) {
				httpcounter++; //checks to see if port is 80 --common port for application layer attack --http flood
			}if (e==53) {
				dnscntr++;//checks to see if port is 80 --common port for DNS flood attack
			}}
		System.out.println("------------------------Results-------------------------------");
		System.out.println("Total amount of Ports received: "+sport2.size());
		System.out.println("Amount of duplicate source ports:" + duport + "\nList of dipulicate port's are: "+countDPort2.toString());
		if (duport ==0) {
			System.out.println("Suspected attack as regular traffic would include many duplicated ports on source end");
		}
		System.out.println("Amount of unique source ports are: "+ portcnt +" Which are: "+countDPort.toString());
		return countDPort;
		
	}



	private static ArrayList<Long> checkDestPort(ArrayList<Long> dport2) {
		ArrayList<Long> countDPort = new ArrayList<Long>();
		ArrayList<Long> countDPort2 = new ArrayList<Long>(); //for duplicant port
		ArrayList<Long> dups = new ArrayList<Long>();
		int duport=0, portcnt=0, httpcounter=0,dnscntr=0;;
		for(int a = 0; a<dport2.size();a++) {
			long currentIP = dport2.get(a);
			if (countDPort.contains(currentIP)) {
					if(countDPort2.contains(currentIP)==false)  {
						countDPort2.add(currentIP);
					}else {
						dups.add(currentIP); //adds extra duplicats to list for further analysis
					}
					
				duport++;
			}else {
				countDPort.add(currentIP);
			portcnt++;	
			}
		
	}
		for(long e: dups) {
			if (e == 80) {
				httpcounter++; //checks to see if port is 80 --common port for application layer attack --http flood
			}if (e==53) {
				dnscntr++;//checks to see if port is 80 --common port for DNS flood attack
			}
		}
		if (httpcounter > (dport2.size()/2)) {
			System.out.println("Suspected App layer attack on http protocol, suspect http flood atack");
		}if (dnscntr > (dport2.size()/2)) {
			System.out.println("Suspected App layer attack on DNS protocol, suspect DNS flood atack");
		}
		
		System.out.println("------------------------Results-------------------------------");
		System.out.println("Total amount of Ports received: "+dport2.size());
		System.out.println("Amount of duplicate destination ports:" + duport + "\nList of dipulicate port's are: "+countDPort2.toString());
		System.out.println("Amount of unique destination ports are: "+ portcnt +" Which are: "+countDPort.toString());
		return countDPort;
	
	}

	private static long getAvgPacket(ArrayList<Long> inPckts2, ArrayList<Long> inBytes2) {
		ArrayList<Long> count = new ArrayList<Long>();
		ArrayList<Long> countbt = new ArrayList<Long>();
		int Cnter=0;
		long sum = 0, avg = 0;
		for(int i=0;i<inPckts2.size();i++) {
			sum = inPckts2.get(i);
			if (i>50) {
				if(inPckts2.get(i) == inPckts2.get(i-10)) {
					Cnter++;
				}if(Cnter >5) {
					Cnter =75;
				}}
			count.add(sum);
		}
		for (Long bg : count) {
			avg +=bg;
		}
		avg = avg /count.size();
		System.out.println("Average packet size is: " +avg  );
			if (Cnter ==75) {
				System.out.println("Possible Attack/Botnet Activity \nHigh volume of constant size packets");
			}
			
			//get bytes per packet
			avg=0; //reset average
			long sndsum=0;
			for(int i=0;i<inPckts2.size();i++) {
				sum =  inBytes2.get(i) / inPckts2.get(i) ;
				sndsum =sndsum + inBytes2.get(i);
				countbt.add(sum);
			//	System.out.println("Bytes per packet for packet "+i+" is "+sum ); //print out to see if working
			}
				for (Long bg : countbt) {
					avg +=bg;
				}
			avg = avg /countbt.size();
			System.out.println("Avg bytes per packet is: "+ avg);
			System.out.println("total number of bytes: "+sndsum);
			sndsum = sndsum/inBytes2.size();
			System.out.println("AVG bytes: "+sndsum);
			setAvgBytes(sndsum);
			
			Long common = mostCommon(inPckts2);
			System.out.println("Most common packet size is "+common);
			
			return avg;
	}
	
	
	//normal traffic should have larger bytes sizes
	private static void setAvgBytes(long sndsum) {
		if ( sndsum > bytesAvg) {
		bytesAvg = sndsum;}
		else {
			setTestBytes(sndsum);
		}
		
	}
	//sets attack bytes size for comparision
	private static void setTestBytes(long sndsum) {
		testBytesAvg = sndsum;
		
	}

	private static long getDifference(ArrayList<Long> fswitch2, ArrayList<Long> lswitch2) {
		ArrayList<Long> count = new ArrayList<Long>();
		int diffCnter=0;
		long sum, avg = 0;
		for(int i=0;i<fswitch2.size();i++) {
			sum = lswitch2.get(i) - (fswitch2.get(i));	
				if (sum ==0) {
					diffCnter++;
				}if(diffCnter >75) {
					diffCnter =75;
				}
			count.add(sum);
			for (Long bg : count) {
				avg +=bg;
			}
		}avg = avg /count.size();
		System.out.println("average time difference is: " +avg  +" Nanoseconds");
			if (diffCnter ==75) {
				System.out.println("Possible Attack/Botnet Activity \nHigh volume of traffic in short time");
			}else {
				System.out.println("Regular traffic");
			}
			return avg; //returns avg time
	}

	//reads in attack traffic
	private static void readUndPrintCSV() {
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(botnetAttackFLowData));
			String line = null;
			reader.readLine(); //reads first line
			while ((line = reader.readLine()) != null) {
				
				String[] words = line.split(",");
				if (words[13].equals('"')){
						System.out.println("true"); //attempt to remove " from data as it is useless
			}
				srcIP.add(words[0]); //string
				dstIP.add(words[1]); //string
				inPckts.add(new Long(words[4]));
				inBytes.add(new Long(words[5]));
				Fswitch.add(new Long(words[6]));
				Lswitch.add(new Long(words[7]));
				Sport.add(new Long(words[8]));
				Dport.add(new Long(words[9]));
				TCP.add(words[10]); //string
				protocol.add(new Long(words[11]));
				secSrcDst.add(words[12]);
				secDstSrc.add(words[13]); //
				
				}			//uniform size 
		/*	for ( int i=0;i<srcIP.size();i++) {
				System.out.println(srcIP.get(i)+ "\t" + dstIP.get(i) +"\t"+inPckts.get(i)+"\t"+inBytes.get(i)
				+"\t"+Fswitch.get(i) +"\t"+Lswitch.get(i)+"\t"+Sport.get(i) +"\t"+Dport.get(i) 
				+"\t"+TCP.get(i) +"\t"+protocol.get(i) 
				+"\t"+secSrcDst.get(i) +"\t"+secDstSrc.get(i));
				
			}*/
			
			//calling test methods
			
			getStringMedian(srcIP);
			getDifference(Fswitch, Lswitch); //gets time difference
			getAvgPacket(inPckts,inBytes);
			checkDestPort(Dport); //checks to see if a specific port is targetted
			checkSrcPort(Sport);
			
			
			
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	private static void getStringMedian(ArrayList<String> srcIP2) {
		ArrayList<String> Sip = new ArrayList<String>();
		ArrayList<String> SipDup = new ArrayList<String>();
		int count=0;
		int Dupcount=0;
		for(int a = 0; a<srcIP2.size();a++) {
			String currentIP = srcIP2.get(a);
			if (Sip.contains(currentIP)) {
					if(SipDup.contains(currentIP)==false)  {
						SipDup.add(currentIP);
					}
				Dupcount++;
			}else {
				Sip.add(currentIP);
			count++;	
			}
			
		}
		//check to see if SipDup contains more then 1 ip addresses, if only contains 1, indicates command point.
		//no point if less then 100 ips 
		if(Sip.size()>=100) {
		botnetcheckMaster(SipDup);
		}
		
		
		System.out.println("------------------------Results-------------------------------");
		System.out.println("Total amount of IP addresses received: "+srcIP2.size());
		System.out.println("Amount of duplicate IP addresses:" + Dupcount + "\nList of dipulicate IP's are: "+SipDup.toString());
		System.out.println("Amount of unique IP addresses are: "+ count);
	}

	private static void botnetcheckMaster(ArrayList<String> sipDup) {
		String check = sipDup.get(0);
		int botnetcnt=0;
		for (int b = 0;b <sipDup.size();b++) {
			if (sipDup.get(b).equals(check)) {
				botnetcnt++;
			}
		}
		if(botnetcnt%2 ==1) {
			botnetcnt++; //makes it even
		}
		if (botnetcnt >= (sipDup.size()/2) ) {  //crude method to determine if ip is command ip of botnet
												//can be easilly beaten by anyway decent botnet
			System.out.println("-------------------------------------------------------------------------------------");
			System.out.println("\nPotential Control IP of botnet found");
			System.out.println("IP address: "+check + "");
			System.out.println("-------------------------------------------------------------------------------------");
		}
	}
		

private static void readNewsite() {
System.out.println("------------------------Features from packet capture flow from looking up news websites-------------------\n");
BufferedReader reader = null;
try {
	reader = new BufferedReader(new FileReader(newsite));
	String line = null;
	reader.readLine(); //reads first line
	while ((line = reader.readLine()) != null) {
		
		String[] words = line.split(",");
		//if (words[13].equals('"')){
		//		System.out.println("true"); //attempt to remove " from data as it is useless
//	}
		srcIP.add(words[2]); //string
		dstIP.add(words[3]); //string
		inPckts.add(new Long(words[5]));
		
		}			//uniform size 
	/*for ( int i=0;i<srcIP.size();i++) {
		System.out.println(srcIP.get(i)+ "\t" + dstIP.get(i) +"\t"+inPckts.get(i));
	}*/
	
	getStringMedian(srcIP);
	//getDifference(Fswitch, Lswitch); //gets time difference
	//getAvgPacket(inPckts, inBytes);
	//checkDestPort(Dport); //checks to see if a specific port is targetted
	getNewsAvgPackets(inPckts);
} catch (FileNotFoundException e) {
	e.printStackTrace();
} catch (IOException e) {
	e.printStackTrace();
} finally {
	if (reader != null) {
		try {
			reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
}

private static void getNewsAvgPackets(ArrayList<Long> inPckts2) {
	ArrayList<Long> count = new ArrayList<Long>();
	int Cnter=0;
	long sum = 0, avg = 0;
	for(int i=0;i<inPckts2.size();i++) {
		sum = inPckts2.get(i);
		if (i>50) {
			if(inPckts2.get(i) == inPckts2.get(i-10)) {
				Cnter++;
			}if(Cnter >5) {
				Cnter =75;
			}}
		count.add(sum);
	}
	for (Long bg : count) {
		avg +=bg;
	}
	avg = avg /count.size();
	System.out.println("Average packet size is: " +avg  );
		if (Cnter ==75) {
			System.out.println("Possible Attack/Botnet Activity \nHigh volume of constant size packets");
		}else {
			System.out.println("Regular traffic");
		}
		
		Long common = mostCommon(inPckts2);
		
		System.out.println("Most common packet size is "+common);
		
		
}


public static <T> T mostCommon(ArrayList<T> list) {
	//credit for code
	//https://stackoverflow.com/questions/19031213/java-get-most-common-element-in-a-list
    Map<T, Integer> map = new HashMap<>();

    for (T t : list) {
        Integer val = map.get(t);
        map.put(t, val == null ? 1 : val + 1);
    }

    Entry<T, Integer> max = null;

    for (Entry<T, Integer> e : map.entrySet()) {
        if (max == null || e.getValue() > max.getValue())
            max = e;
    }

    return max.getKey();
}

private static void readVOD() {
	System.out.println("\n------------------------Features from packet capture flow from Video on Demmand services-------------------\n");

	BufferedReader reader = null;
	try {
		reader = new BufferedReader(new FileReader(vod));
		String line = null;
		reader.readLine(); //reads first line
		while ((line = reader.readLine()) != null) {
			
			String[] words = line.split(",");
			//if (words[13].equals('"')){
			//		System.out.println("true"); //attempt to remove " from data as it is useless
//		}
			srcIP.add(words[2]); //string
			dstIP.add(words[3]); //string
			inPckts.add(new Long(words[5]));
			
			}			//uniform size 
		/*for ( int i=0;i<srcIP.size();i++) {
			System.out.println(srcIP.get(i)+ "\t" + dstIP.get(i) +"\t"+inPckts.get(i));
		}*/
		
		getStringMedian(srcIP);
		//getDifference(Fswitch, Lswitch); //gets time difference
		//getAvgPacket(inPckts, inBytes);
		//checkDestPort(Dport); //checks to see if a specific port is targetted
		getNewsAvgPackets(inPckts);
	} catch (FileNotFoundException e) {
		e.printStackTrace();
	} catch (IOException e) {
		e.printStackTrace();
	} finally {
		if (reader != null) {
			try {
				reader.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	}
	
}
