package net.floodlightcontroller.knnips;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.Match.Builder;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFPortBitMap;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.python.antlr.ast.List;
import org.python.modules.math;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.ForwardingBase;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KnnIps implements IOFMessageListener, IFloodlightModule,IOFSwitchListener {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected ArrayList<IOFSwitch> APs;
	public boolean adjacency[][];

	protected IOFSwitchService switchService;
	protected IOFSwitch sw;
	protected IOFSwitch currentAP;

	protected String csvFile;
	protected int counter;
	protected BufferedReader br;
	protected String line;
	protected double[] myindex;
	protected double[] euclidean;
	protected int[] euindex;
	ArrayList<Double[]> arr;	
	ArrayList<Integer> outindices;	
	
	Ethernet l2;
	IPv4 l3;
	UDP l4;
	Data l7;
	
	@Override
	public String getName() {
	return KnnIps.class.getSimpleName();
	}
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
//		return (type.equals(OFType.PACKET_IN) && (name.equals("forwarding") || name.equals("linkdiscovery") || name.equals("topology")));
//		return (type.equals(OFType.PACKET_IN) && true);
		
		if (type == OFType.PACKET_IN) {
//            logger.info("RECEIVED PACKET_IN: PROCESSING FIRST....name:{}",name);
            return true;
        }
        return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
		new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		macAddresses = new ConcurrentSkipListSet<Long>();
		switchService = context.getServiceImpl(IOFSwitchService.class);
		logger = LoggerFactory.getLogger(KnnIps.class);
		APs=new ArrayList<IOFSwitch>();
		adjacency = new boolean[7][7];
		adjacency[0][1]=true;
		adjacency[0][3]=true;
		adjacency[0][4]=true;
		adjacency[1][0]=true;
		adjacency[1][2]=true;
		adjacency[1][4]=true;
		adjacency[1][5]=true;
		adjacency[2][1]=true;
		adjacency[2][5]=true;
		adjacency[2][6]=true;
		adjacency[3][0]=true;
		adjacency[3][4]=true;
		adjacency[4][0]=true;
		adjacency[4][1]=true;
		adjacency[4][3]=true;
		adjacency[4][5]=true;
		adjacency[5][1]=true;
		adjacency[5][2]=true;
		adjacency[5][4]=true;
		adjacency[5][6]=true;
		adjacency[6][2]=true;
		adjacency[6][5]=true;
		
//		l2 = new Ethernet();
//		l3 = new IPv4();
//		l4 = new UDP();
//		l7 = new Data();
		
		counter=0;
		myindex=new double[]{-100,-100,-100,-100,-100,-100,-100};
		euclidean=new double[175];
		euindex=new int[175];
		csvFile = "./fp5m.csv";
		line="";
		arr=new ArrayList<Double[]>();
		outindices=new ArrayList<Integer>();
		for (int i = 0; i < euindex.length; i++)
			euindex[i]=i;
		
		try {

            br = new BufferedReader(new FileReader(csvFile));
            while ((line = br.readLine()) != null) {

                // use comma as separator
            	Double[] mya=new Double[12];
                String[] ind = line.split(",");
                for (int i = 0; i < ind.length; i++) {
                	mya[i]=Double.parseDouble(ind[i]);
				}
                for (int i = 11; i < mya.length; i++) {
					mya[i]=0.0;
				}
                arr.add(mya);
                
            }
//            System.out.println("----------------------------------------");
//            for (int i=0; i<myindex.length; i++) {
//            	for (Double[] a : arr){
//                	a[i+11]=Math.pow(myindex[i]-a[i+4],2);
//                }
//            }
            
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
	
	
	}

	public int partition(int start, int end) 
    {
        int i = start + 1;
        int j = i;
        int pivot = start;
        for (; i < end; i++) 
        {
            if (euclidean[i] < euclidean[pivot]) 
            {
            	//swap A(i),A(j)
                double temp=euclidean[i];
                euclidean[i]=euclidean[j];
                euclidean[j]=temp;
                
                int t=euindex[i];
                euindex[i]=euindex[j];
                euindex[j]=t;    
                
                j++;
            }
        }
        if (j <= end) {
        	//swap A(pivot),A(j-1)
        	double temp=euclidean[pivot];
        	euclidean[pivot]=euclidean[j-1];
        	euclidean[j-1]=temp;
	        
	        int t=euindex[pivot];
	        euindex[pivot]=euindex[j-1];
	        euindex[j-1]=t;
	    }
        return j - 1;
    }
    public void quick_sort(int start, int end, int K) {
    	int part;
        if (start < end) 
        {
            part = partition(start, end);
            if (part == K - 1) {
//                System.out.println("kth smallest element : " + euclidean[part]+" and the index is: "+(euindex[part]+1));
                outindices.add(euindex[part]);
            }
            if (part > K - 1)
                quick_sort(start, part, K);
            else
                quick_sort(part + 1, end, K);
        }
        return;
    }
	
	@Override
	public void startUp(FloodlightModuleContext context) {
	floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	switchService.addOFSwitchListener(this);
	logger.info("KnnIps has been  Started!!");
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive
	 (IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		switch (msg.getType()) {
	    case PACKET_IN:
	        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	        
		    if (eth.getEtherType()==EthType.ARP){
		    	ARP arp=(ARP)eth.getPayload();
	        	if(arp.getTargetProtocolAddress().equals(IPv4Address.of("10.0.0.1")) &&
	        			arp.getSenderProtocolAddress().equals(IPv4Address.of("10.0.1.1"))){
	        		logger.info("ARP REQ recieved");
	        		currentAP=sw;
	        		for (int i = 0; i < APs.size(); i++) {	
	        			
	        			String apmac=APs.get(i).getId().toString().substring(6);
	        			String apip=APs.get(i).getInetAddress().toString().substring(sw.getInetAddress()
	        					.toString().indexOf('/')+1, sw.getInetAddress().toString().indexOf(':'));
	        			l2 = new Ethernet();
		                l2.setSourceMACAddress(MacAddress.of("12:12:12:12:12:12"));
		                l2.setDestinationMACAddress(MacAddress.of(apmac));
		                l2.setEtherType(EthType.IPv4);
		                
		                l3 = new IPv4();
		                l3.setSourceAddress(IPv4Address.of("10.0.0.1"));
		                l3.setDestinationAddress(IPv4Address.of(apip));
		                l3.setTtl((byte) 64);
		                l3.setProtocol(IpProtocol.UDP);
		                
		                l4 = new UDP();
		                l4.setSourcePort(TransportPort.of(9999));
		                l4.setDestinationPort(TransportPort.of(7777));
		                
		                l7 = new Data();
		                String ss="send,"+eth.getSourceMACAddress();
		                byte[] dta=ss.getBytes();
		                
		                l7.setData(dta);
		                
		                l2.setPayload(l3);
		                l3.setPayload(l4);
		                l4.setPayload(l7);
		                
		                byte[] serializedData = l2.serialize();
		                
		                OFPacketOut po = sw.getOFFactory().buildPacketOut() /* mySwitch is some IOFSwitch object */
		                	    .setData(serializedData)
		                	    .setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.LOCAL, 0xffFFffFF)))
		                	    .setInPort(OFPort.CONTROLLER)
		                	    .build();
//		                if (APs.contains(sw)) {
//		                	int dpid_ap=Integer.parseInt(sw.getId().toString().substring(18,20));
//		                
//			                for (int j = 0; j < adjacency.length; j++) {
//	                			if (adjacency[dpid_ap][j]) {
//	                				APs.get(j).write(po);
//								}
//	            			}
//		                	sw.write(po);
//		                }
		                
		                APs.get(i).write(po);
					}
		                
		            return Command.STOP;
	        	}
	        }
		    else if (eth.getEtherType()==EthType.IPv4){
		    	IPv4 ipv4=(IPv4)eth.getPayload();
	        	
	        	if(ipv4.getProtocol().equals(IpProtocol.UDP)){
	        		UDP udp = (UDP)ipv4.getPayload();
//	        		TransportPort srcport=udp.getSourcePort();
//	        		TransportPort dstport=udp.getDestinationPort();
	        		if (Integer.parseInt(udp.getDestinationPort().toString()) == 8888){
	        			
	        			Data dataPkt = (Data) udp.getPayload();
	                    
//	        			System.out.println("length "+dataPkt.getData().length);
	                    
	                    byte[] arrb = dataPkt.getData();
	                    String s="";
	                    for (int i = 0; i < arrb.length; i++){
	                            s+=(char)arrb[i];
	                    }
	                    s=sw.getId()+","+s;
//	                    System.out.println(s);
	                    
//	                    String metadata=s.split(",");
//	                    for (int i = 0; i < metadata.length; i++){
//	                    	System.out.println(i+" "+metadata[i]);
//						}
	                    int apinx=Integer.parseInt(sw.getId().toString().substring(18,20));
	                    if (counter<6) {
							myindex[apinx]=Double.parseDouble(s.split(",")[2]);
							counter++;
						}
	                    else if(counter==6){
	                    	int x=0;
	                    	for (Double[] a : arr){
	                    		for (int i=0; i<myindex.length; i++) {
									a[11]+=Math.pow(myindex[i]-a[i+4],2);
								}
	                    		a[11] = Math.sqrt(a[11]);
	                    		euclidean[x]=a[11];
	                    		x++;
							}
//							System.out.println("----------------------------------------");
//		                    for (Double[] i : arr) {
//		                    	for (Double inx : i) {
//		                    		System.out.print(inx+", ");
//		                    	}
//		                      	System.out.println();
//		                    }
//							System.out.println("========================================");
							
							quick_sort(0, 175, 1);
							quick_sort(0, 175, 2);
							quick_sort(0, 175, 3);
							quick_sort(0, 175, 4);
							quick_sort(0, 175, 5);
							quick_sort(0, 175, 6);
							quick_sort(0, 175, 7);
							
							double w0=1/euclidean[0];
							double w1=1/euclidean[1];
							double w2=1/euclidean[2];
							double w3=1/euclidean[3];
							double w4=1/euclidean[4];
							double w5=1/euclidean[5];
							double w6=1/euclidean[6];
							
							double wsum=w0+w1+w2+w3+w4+w5+w6;
							
							double ww0=w0/wsum;
							double ww1=w1/wsum;
							double ww2=w2/wsum;
							double ww3=w3/wsum;
							double ww4=w4/wsum;
							double ww5=w5/wsum;
							double ww6=w6/wsum;
						  
							double ex=ww0*(arr.get(outindices.get(0))[1])+
									  ww1*(arr.get(outindices.get(1))[1])+
								  	  ww2*(arr.get(outindices.get(2))[1])+
								  	  ww3*(arr.get(outindices.get(3))[1])+
								  	  ww4*(arr.get(outindices.get(4))[1])+
								  	  ww5*(arr.get(outindices.get(5))[1])+
								  	  ww6*(arr.get(outindices.get(6))[1]);
						  
						    double ey=ww0*(arr.get(outindices.get(0))[2])+
							   	  	  ww1*(arr.get(outindices.get(1))[2])+
								  	  ww2*(arr.get(outindices.get(2))[2])+
								  	  ww3*(arr.get(outindices.get(3))[2])+
								  	  ww4*(arr.get(outindices.get(4))[2])+
								  	  ww5*(arr.get(outindices.get(5))[2])+
								  	  ww6*(arr.get(outindices.get(6))[2]);
						  
//						    System.out.println(ex+" "+ey);
						    
						    l2 = new Ethernet();
			                l2.setSourceMACAddress(MacAddress.of("12:12:12:12:12:12"));
			                l2.setDestinationMACAddress("00:00:00:00:00:01");
			                l2.setEtherType(EthType.IPv4);
//			                
			                l3 = new IPv4();
			                l3.setSourceAddress(IPv4Address.of("10.0.0.1"));
			                l3.setDestinationAddress("10.0.1.1");
			                l3.setTtl((byte) 64);
			                l3.setProtocol(IpProtocol.UDP);
//			                
			                l4 = new UDP();
			                l4.setSourcePort(TransportPort.of(9999));
			                l4.setDestinationPort(TransportPort.of(9898));
//			                
			                l7 = new Data();
			                String ss=Double.toString(ex)+","+Double.toString(ey);
			                byte[] dta=ss.getBytes();
			                
			                l7.setData(dta);
			                
			                l2.setPayload(l3);
			                l3.setPayload(l4);
			                l4.setPayload(l7);
			                
			                byte[] serializedData = l2.serialize();
			                
			                OFPacketOut po = sw.getOFFactory().buildPacketOut() /* mySwitch is some IOFSwitch object */
			                	    .setData(serializedData)
			                	    .setActions(Collections.singletonList((OFAction) sw.getOFFactory().actions().output(OFPort.of(1), 0xffFFffFF)))
			                	    .setInPort(OFPort.CONTROLLER)
			                	    .build();
			                currentAP.write(po);
						  
						    counter=0;
//						    arr=new ArrayList<Double[]>();
						    outindices=new ArrayList<Integer>();
						    w0=0;
						    w1=0;
						    w2=0;
						    w3=0;
						    w4=0;
						    w5=0;
						    w6=0;
						    ww0=0;
						    ww1=0;
						    ww2=0;
						    ww3=0;
						    ww4=0;
						    ww5=0;
						    ww6=0;
						    ex=0;
						    ey=0;
						    euclidean=new double[175];
							for (int i = 0; i < euindex.length; i++)
								euindex[i]=i;
							for (Double[] i : arr)
								i[11] = 0.0;
	                    }
	                    
	                    
		            return Command.STOP;
	        		}
	        	}
	        }	        
	        break;
	    default:
	        break;
	    }
	    return Command.CONTINUE;
	}
	
	@Override
	public void switchAdded(DatapathId switchId) {
		sw=switchService.getActiveSwitch(switchId);
		if (sw != null){
//			if (Integer.parseInt(sw.getId().toString().substring(0,2)) == apdpid){
//				accesspoints.add(sw);
////				System.out.println("++++++++++++++++++++++++++++++");
			if (sw.getId().toString().substring(6,8).contains("02")){	
//				if (sw.getId().toString().substring(21,23).contains("01")){
				APs.add(sw);
				
//				}
			}
		}
//		if (APs.size()==7) {
//			logger.info("Adjacency Matrix");
//			for (int i = 0; i < adjacency.length; i++) {
//				for (int j = 0; j < adjacency.length; j++) {
//					System.out.print(adjacency[i][j]+"\t");
//				}
//				System.out.println();
//			}
//		}
	}
	
	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}
	@Override
	public void switchDeactivated(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}
}