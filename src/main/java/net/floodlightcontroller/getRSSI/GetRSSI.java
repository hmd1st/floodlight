package net.floodlightcontroller.getRSSI;

import java.util.Collection;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;
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

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
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

public class GetRSSI implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;

	@Override
	public String getName() {
	return GetRSSI.class.getSimpleName();
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
	logger = LoggerFactory.getLogger(GetRSSI.class);
	}


	@Override
	public void startUp(FloodlightModuleContext context) {
	floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	logger.info("Get RSSI has been  Started!!");
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive
	 (IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		switch (msg.getType()) {
	    case PACKET_IN:
	        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
	        
		    if (eth.getEtherType()==EthType.IPv4){
		    	IPv4 ipv4=(IPv4)eth.getPayload();
	        	
	        	if(ipv4.getProtocol().equals(IpProtocol.UDP)){
	        		UDP udp = (UDP)ipv4.getPayload();
//	        		TransportPort srcport=udp.getSourcePort();
//	        		TransportPort dstport=udp.getDestinationPort();
	        		if (Integer.parseInt(udp.getDestinationPort().toString()) == 8888){
	        			
	        			Data dataPkt = (Data) udp.getPayload();
	                    
//	        			System.out.println("length "+dataPkt.getData().length);
	                    
	                    byte[] arr = dataPkt.getData();
	                    String s="";
	                    for (int i = 0; i < arr.length; i++){
	                            s+=(char)arr[i];
	                    }
	                    s=sw.getId()+","+s;
	                    System.out.println(s);
//	                    String metadata=s.split(",");
//	                    for (int i = 0; i < metadata.length; i++){
//	                    	System.out.println(i+" "+metadata[i]);
//						}
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
	
}