import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

class Packet	{
	String direction;
	String protocol;
	String port;
	String IPAddress;
	
	public Packet(String direction, String protocol, String port, String IPAddress)	{
		this.direction = direction;
		this.protocol = protocol;
		this.port = port;
		this.IPAddress = IPAddress;
	}
	
	public String toString()	{
		return direction + " " + protocol + " " + port + " " + IPAddress;
	}
}

public class Firewall {
	BufferedReader br;
	static List<Packet> list;
	
	Firewall(String pathToCsvFile)	{
		list = new ArrayList<Packet>();
		try	{
			String line;
			br = new BufferedReader(new FileReader(pathToCsvFile));
			line = br.readLine();
			while((line = br.readLine()) != null)	{
				String[] packetArray = line.split(",");
				list.add(new Packet(packetArray[0], packetArray[1], packetArray[2], packetArray[3]));
			}
		} catch(Exception e)	{
			e.printStackTrace();
		}
	}
	
	public boolean accept(String direction, String protocol, String port, String IPAddress)	{
		// Check direction
		direction = direction.toLowerCase();
		if(!(direction.equalsIgnoreCase("inbound") || direction.equalsIgnoreCase("outbound")))	{
			return false;
		}
		
		// Check protocol
		if(!(protocol.equalsIgnoreCase("tcp") || protocol.equalsIgnoreCase("udp")))	{
			return false;
		}
		
		// Check port
		try	{
			if(port.contains("-"))	{
				// Range is present
				String[] portRange = port.split("-");
				int startRange = Integer.parseInt(portRange[0]);
				int endRange = Integer.parseInt(portRange[1]);
				if(!(startRange < endRange))	{
					return false;
				}
				if(!(startRange >= 1 && startRange <= 65535))	{
					return false;
				}
				if(!(endRange >= 1 && endRange <= 65535))	{
					return false;
				}
			}	else	{
				// Single port present
				int singlePort = Integer.parseInt(port);
				if(!(singlePort >= 1 && singlePort <= 65535))	{
					return false;
				}
			}
		} catch(Exception e)	{
			return false;
		}
		
		// Check IP Address
		try	{
			if(!IPAddress.contains("-"))	{
				// Single IPV4 present
				
				// Check octet
				String[] octetRange = IPAddress.split("\\.");
				int octet_1 = Integer.parseInt(octetRange[0]);
				int octet_2 = Integer.parseInt(octetRange[1]);
				int octet_3 = Integer.parseInt(octetRange[2]);
				int octet_4 = Integer.parseInt(octetRange[3]);
				
				if(!(octet_1 >= 0 && octet_1 <= 255 && octet_2 >= 0 && octet_2 <= 255 && octet_3 >= 0 && octet_3 <= 255 && octet_4 >= 0 && octet_4 <= 255))	{
					return false;
				}
			}	else if (IPAddress.contains("-"))	{
				// IPV4 Range Present
				String[] splittedIPV4 = IPAddress.split("-");
				String IPV4_1 = splittedIPV4[0];
				String IPV4_2 = splittedIPV4[1];
				
				String[] octetRange;
				
				// Check octet 1
				octetRange = IPV4_1.split("\\.");
				int octet_1_1 = Integer.parseInt(octetRange[0]);
				int octet_1_2 = Integer.parseInt(octetRange[1]);
				int octet_1_3 = Integer.parseInt(octetRange[2]);
				int octet_1_4 = Integer.parseInt(octetRange[3]);
				
				if(!(octet_1_1 >= 0 && octet_1_1 <= 255 && octet_1_2 >= 0 && octet_1_2 <= 255 && octet_1_3 >= 0 && octet_1_3 <= 255 && octet_1_4 >= 0 && octet_1_4 <= 255))	{
					return false;
				}
				
				// Check octet 2
				octetRange = IPV4_2.split("\\.");
				int octet_2_1 = Integer.parseInt(octetRange[0]);
				int octet_2_2 = Integer.parseInt(octetRange[1]);
				int octet_2_3 = Integer.parseInt(octetRange[2]);
				int octet_2_4 = Integer.parseInt(octetRange[3]);
				
				if(!(octet_2_1 >= 0 && octet_2_1 <= 255 && octet_2_2 >= 0 && octet_2_2 <= 255 && octet_2_3 >= 0 && octet_2_3 <= 255 && octet_2_4 >= 0 && octet_2_4 <= 255))	{
					return false;
				}
				
				// Check Range proper
				if(!(octet_1_1 <= octet_2_1))	{
					return false;
				}
				if(!(octet_1_2 <= octet_2_2))	{
					return false;
				}
				if(!(octet_1_3 <= octet_2_3))	{
					return false;
				}
				if(!(octet_1_4 <= octet_2_4))	{
					return false;
				}
			}	else	{
				return false;
			}
		}	catch(Exception e)	{
			return false;
		}
		return true;
	}

	public static void main(String[] args) {
		Firewall fw = new Firewall("dataset.csv");
		for(Packet p: list)	{
			System.out.println(p);
			System.out.println(fw.accept(p.direction, p.protocol, p.port, p.IPAddress));
		}
	}

}
